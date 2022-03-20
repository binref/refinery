#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List, Optional
from math import log2

from refinery.units.crypto.cipher import StandardBlockCipherUnit, Arg
from refinery.units.crypto.cipher.rc5 import rc5constants
from refinery.lib import chunks
from refinery.lib.crypto import (
    rotr,
    rotl,
    BlockCipher,
    BlockCipherFactory,
    CipherMode,
    SpecifiedAtRuntime,
    BufferType,
)


class RC6(BlockCipher):

    block_size: int
    valid_key_sizes = range(256)
    _S: List[int]
    _w: int
    _r: int
    _u: int
    _m: int
    _g: int

    def __init__(self, w: int, r: int, key: BufferType, mode: Optional[CipherMode] = None):
        if w < 8 or w % 8:
            raise ValueError(F'Invalid word size: {w}')
        self._w = w
        self._u = w // 8
        self._r = r
        self._g = int(log2(w))
        self._m = (1 << w) - 1
        super().__init__(key, mode)

    @property
    def block_size(self):
        return self._u * 4

    def block_decrypt(self, block) -> BufferType:
        u = self._u
        w = self._w
        g = self._g
        r = self._r
        M = self._m
        S = self._S
        A, B, C, D = chunks.unpack(block, u)
        C = C - S[2 * r + 3] & M
        A = A - S[2 * r + 2] & M
        for i in range(r, 0, -1):
            A, B, C, D = D, A, B, C
            t = rotl(w, B * (2 * B + 1) & M, g)
            v = rotl(w, D * (2 * D + 1) & M, g)
            C = rotr(w, C - S[2 * i + 1] & M, t) ^ v
            A = rotr(w, A - S[2 * i + 0] & M, v) ^ t
        D = D - S[1] & M
        B = B - S[0] & M
        return chunks.pack((A, B, C, D), u)

    def block_encrypt(self, block) -> BufferType:
        u = self._u
        w = self._w
        g = self._g
        r = self._r
        M = self._m
        S = self._S
        A, B, C, D = chunks.unpack(block, u)
        B = B + S[0] & M
        D = D + S[1] & M
        for i in range(1, r + 1):
            t = rotl(w, B * (2 * B + 1) & M, g)
            v = rotl(w, D * (2 * D + 1) & M, g)
            A = rotl(w, A ^ t, v) + S[2 * i + 0] & M
            C = rotl(w, C ^ v, t) + S[2 * i + 1] & M
            A, B, C, D = B, C, D, A
        A = A + S[2 * r + 2] & M
        C = C + S[2 * r + 3] & M
        return chunks.pack((A, B, C, D), u)

    @property
    def key(self):
        return self._S

    @key.setter
    def key(self, key):
        w = self._w  # word size
        u = self._u  # length of a word in bytes
        r = self._r  # round count
        M = self._m  # bit mask
        L = list(chunks.unpack(key + (-len(key) % u) * B'\0', u))
        c = len(L)
        t = 2 * (r + 2)
        P, Q = rc5constants(w)
        S = [P]
        while len(S) < t:
            S.append(S[~0] + Q & M)
        i = j = 0
        A = B = 0
        for _ in range(3 * max(t, c)):
            A = S[i] = rotl(w, S[i] + A + B & M, 3)
            B = L[j] = rotl(w, L[j] + A + B & M, A + B)
            i = (i + 1) % t
            j = (j + 1) % c
        self._S = S


class rc6(StandardBlockCipherUnit, cipher=SpecifiedAtRuntime):
    """
    RC6 encryption and decryption. The parameter defaults are the RC6 parameters that were chosen
    for the AES candidacy. Only key sizes of 128, 192, and 256 bits are used for AES candidates, but
    the unit will allow any key size up to 256 bits.
    """
    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False,
        rounds    : Arg.Number('-k', help='Number of rounds to use, the default is {default}') = 20,
        word_size : Arg.Number('-w', help='The word size in bits, {default} by default.') = 32
    ):
        class _R(RC6):
            def __init__(self, key: BufferType, mode: Optional[CipherMode] = None):
                super().__init__(word_size, rounds, key, mode)
            block_size = word_size // 2
        if word_size % 8:
            raise ValueError('Block size must be a multiple of 16.')
        self._cipher_object_factory = c = BlockCipherFactory(_R)
        self.block_size = c.block_size
        super().__init__(key, iv, padding, mode, raw)
