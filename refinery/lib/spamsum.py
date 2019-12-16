#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This implements the SpamSum fuzzy hashing algorithm.
"""


class RollingHash:
    """
    A simple rolling hash.
    """
    def __init__(self):
        self.h1 = 0
        self.h2 = 0
        self.h3 = 0
        self.w = bytearray(7)
        self.n = 0

    @property
    def digest(self):
        """
        Return the hash digest.
        """
        h = self.h1 + self.h2 + self.h3
        return h & 0xFFFFFFFF

    def update(self, c):
        """
        Feed a new byte `c` to the hash.
        """
        self.h2 = (self.h2 - self.h1) + 7 * c
        self.h1 = (self.h1 + c) - self.w[self.n]
        self.w[self.n] = c
        self.n = (self.n + 1) % 7
        self.h3 = ((self.h3 << 5) ^ c) & 0xFFFFFFFF


def spamsum(data, alphabet=B'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'):
    """
    Return a spamsum hash using the given alphabet.
    """
    def parts(N, seed=0x28021967):
        rh = RollingHash()
        lcg = seed
        k = 0
        B = 3
        while B * N < len(data):
            B <<= 1
        for byte in data:
            rh.update(byte)
            lcg = ((lcg * 0x01000193) ^ byte) & 0xFFFFFFFF
            if not (rh.digest + 1) % B and k < (N - 1):
                yield lcg % N
                k += 1
                lcg = seed
        if rh.digest and lcg != seed:
            yield lcg % N
    return bytes(alphabet[h] for h in parts(len(alphabet)))
