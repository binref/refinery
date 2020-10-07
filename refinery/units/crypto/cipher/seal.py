#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure Python implementation of SEAL3

Reference:
https://link.springer.com/article/10.1007/s001459900048
"""
import struct
from typing import Iterable

from . import StreamCipherUnit
from ....lib.crypto import rotr32


__all__ = ['seal']


class SEAL_Gamma:
    """
    This class implements the key derivation for the SEAL cipher.
    """
    def _process(self, state, w):
        """
        This is a pure Python implementation of a SHA1 Round.
        """
        def lrot(b, n):
            return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF
        for t in range(16, 80):
            w.append(lrot(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]))
        a, b, c, d, e = state
        for t in range(80):
            if t < 20:
                k = 0x5A827999
                f = d ^ (b & (c ^ d))
            elif t < 40:
                k = 0x6ED9EBA1
                f = b ^ c ^ d
            elif t < 60:
                k = 0x8F1BBCDC
                f = (b & c) | (b & d) | (c & d)
            else:
                k = 0xCA62C1D6
                f = b ^ c ^ d
            e = (lrot(5, a) + f + e + w[t] + k) & 0xFFFFFFFF
            a, b, c, d, e = e, a, lrot(30, b), c, d

        return (
            (state[0] + a) & 0xFFFFFFFF,
            (state[1] + b) & 0xFFFFFFFF,
            (state[2] + c) & 0xFFFFFFFF,
            (state[3] + d) & 0xFFFFFFFF,
            (state[4] + e) & 0xFFFFFFFF
        )

    def process(self, w):
        self.state = self._process(self.state, w)

    def apply(self, i):
        sha_index = i // 5
        if sha_index != self.last_index:
            self.D[0] = sha_index
            self.state = tuple(self.H)
            self.process(list(self.D))
            self.last_index = sha_index
        return self.state[i % 5]

    def __init__(self, key, byteswap=True):
        self.last_index = 0xFFFFFFFF
        self.D = 0x10 * [0]
        prefix = '>' if byteswap else '<'
        self.H = struct.unpack(prefix + 'IIIII', key)


class SEAL_Cipher:
    """
    Implementation of the SEAL algorithm. The `byteswap` option can be set
    to false if the key already has the correct byte order to be used as a
    SHA1 state.
    """

    def __init__(self, key, byteswap=True):
        self.gamma = SEAL_Gamma(key, byteswap)
        self.counter_inside = 0
        self.counter_outside = 0
        self.counter_start = 0
        self.iterations_per_count = 4

        self.T = B''.join(
            struct.pack('<I', self.gamma.apply(i)) for i in range(512))

        self.S = [self.gamma.apply(i + 1 * 0x1000) for i in range(256)]
        self.R = [self.gamma.apply(i + 2 * 0x1000) for i in range(16)]

    def ttab(self, index):
        value, = struct.unpack('<I', self.T[index:index + 4])
        return value

    def __iter__(self):

        def rotr9(n):
            return 0xFFFFFFFF & (((n & 0xFFFFFFF) >> 9) | (n << 23))

        while True:
            a =       (      self.counter_outside) ^ self.R[4 * self.counter_inside + 0] # noqa
            b = rotr32(0x08, self.counter_outside) ^ self.R[4 * self.counter_inside + 1] # noqa
            c = rotr32(0x10, self.counter_outside) ^ self.R[4 * self.counter_inside + 2] # noqa
            d = rotr32(0x18, self.counter_outside) ^ self.R[4 * self.counter_inside + 3] # noqa

            def warp():
                nonlocal a, b, c, d
                p = a & 0x7FC; b += self.ttab(p); a = rotr9(a) # noqa
                p = b & 0x7FC; c += self.ttab(p); b = rotr9(b) # noqa
                p = c & 0x7FC; d += self.ttab(p); c = rotr9(c) # noqa
                p = d & 0x7FC; a += self.ttab(p); d = rotr9(d) # noqa

            warp()
            warp()

            w, x, y, z = d, b, a, c

            warp()

            a, b, c, d = a, b, c, d

            for i in range(64):
                p = a & 0x7FC
                a = rotr9(a)
                b += self.ttab(p)
                b ^= a

                q = b & 0x7FC
                b = rotr9(b)
                c ^= self.ttab(q)
                c += b

                p = (p + c) & 0x7FC
                c = rotr9(c)
                d += self.ttab(p)
                d ^= c

                q = (q + d) & 0x7FC
                d = rotr9(d)
                a ^= self.ttab(q)
                a += d

                p = (p + a) & 0x7FC
                b ^= self.ttab(p)
                a = rotr9(a)

                q = (q + b) & 0x7FC
                c += self.ttab(q)
                b = rotr9(b)

                p = (p + c) & 0x7FC
                d ^= self.ttab(p)
                c = rotr9(c)

                q = (q + d) & 0x7FC
                d = rotr9(d)
                a += self.ttab(q)

                a &= 0xFFFFFFFF
                b &= 0xFFFFFFFF
                c &= 0xFFFFFFFF
                d &= 0xFFFFFFFF

                for byte in bytearray(struct.pack('<IIII',
                        (b + self.S[4 * i + 0]) & 0xFFFFFFFF, c ^ self.S[4 * i + 1],
                        (d + self.S[4 * i + 2]) & 0xFFFFFFFF, a ^ self.S[4 * i + 3])):
                    yield byte

                if i & 1:
                    a += y
                    b += z
                    c ^= y
                    d ^= z
                else:
                    a += w
                    b += x
                    c ^= w
                    d ^= x

            self.counter_inside = (self.counter_inside + 1) % self.iterations_per_count

            if not self.counter_inside:
                self.counter_outside += 1


class seal(StreamCipherUnit):
    """
    SEAL encryption and decryption.
    """
    key_sizes = 20

    def keystream(self) -> Iterable[bytes]:
        return SEAL_Cipher(self.args.key)
