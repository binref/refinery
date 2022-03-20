#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import math

from decimal import localcontext, Decimal
from typing import List, Optional
from functools import partial

from refinery.units.crypto.cipher import StandardBlockCipherUnit, Arg
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

itob = partial(int.to_bytes, byteorder='little')
btoi = partial(int.from_bytes, byteorder='little')


def rc5constants(w: int):
    def odd(d: Decimal) -> int:
        x = math.floor(d)
        return x if x % 2 else x + 1
    with localcontext() as ctx:
        ctx.prec = w
        a = Decimal(1).exp() - 2
        b = (1 + Decimal(5).sqrt()) / 2 - 1
        p = 1 << w
        return odd(a * p), odd(b * p)


class RC5(BlockCipher):

    block_size: int
    valid_key_sizes = range(256)
    _S: List[int]
    _w: int
    _r: int
    _u: int
    _m: int

    def __init__(self, w: int, r: int, key: BufferType, mode: Optional[CipherMode] = None):
        if w < 0 or w % 8:
            raise ValueError(F'Invalid word size: {w}')
        self._w = w
        self._u = w // 8
        self._r = r
        self._m = (1 << w) - 1
        super().__init__(key, mode)

    @property
    def block_size(self):
        return self._u * 2

    def block_decrypt(self, block) -> BufferType:
        u = self._u
        w = self._w
        M = self._m
        S = self._S
        A: int = btoi(block[:u])
        B: int = btoi(block[u:])
        for i in range(self._r, 0, -1):
            B = rotr(w, B - S[2 * i + 1] & M, A) ^ A
            A = rotr(w, A - S[2 * i + 0] & M, B) ^ B
        B = B - S[1] & M
        A = A - S[0] & M
        return itob(A, u) + itob(B, u)

    def block_encrypt(self, block) -> BufferType:
        u = self._u
        w = self._w
        M = self._m
        S = self._S
        A: int = btoi(block[:u]) + S[0] & M
        B: int = btoi(block[u:]) + S[1] & M
        for i in range(1, self._r + 1):
            A = rotl(w, A ^ B, B) + S[2 * i + 0] & M
            B = rotl(w, B ^ A, A) + S[2 * i + 1] & M
        return itob(A, u) + itob(B, u)

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
        t = 2 * (r + 1)
        P, Q = rc5constants(w)
        S = [P]
        for i in range(1, t):
            S.append(S[i - 1] + Q & M)
        i = j = 0
        A = B = 0
        for _ in range(3 * max(t, c)):
            A = S[i] = rotl(w, S[i] + A + B & M, 3)
            B = L[j] = rotl(w, L[j] + A + B & M, A + B)
            i = (i + 1) % t
            j = (j + 1) % c
        self._S = S


class rc5(StandardBlockCipherUnit, cipher=SpecifiedAtRuntime):
    """
    RC5 encryption and decryption.
    """
    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False,
        rounds    : Arg.Number('-k', help='Number of rounds to use, the default is {default}') = 12,
        word_size : Arg.Number('-w', help='The word size in bits, {default} by default.') = 32
    ):
        class _R(RC5):
            def __init__(self, key: BufferType, mode: Optional[CipherMode] = None):
                super().__init__(word_size, rounds, key, mode)
            block_size = word_size // 4
        if word_size % 8:
            raise ValueError('Block size must be a multiple of 16.')
        self._cipher_object_factory = c = BlockCipherFactory(_R)
        self.block_size = c.block_size
        super().__init__(key, iv, padding, mode, raw)
