#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List, NamedTuple
from struct import unpack

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import (
    rotl128,
    rotl8,
    rotr8,
    BlockCipher,
    BlockCipherFactory,
    BufferType,
)

M32 = 0x0000000_FFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

SIGMA1 = 0xA09E667F3BCC908B
SIGMA2 = 0xB67AE8584CAA73B2
SIGMA3 = 0xC6EF372FE94F82BE
SIGMA4 = 0x54FF53A5F1D36F1C
SIGMA5 = 0x10E527FADE682D1D
SIGMA6 = 0xB05688C2B3E6C1FD

SBOX1 = [
    0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41,
    0x23, 0xEF, 0x6B, 0x93, 0x45, 0x19, 0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E, 0x1D, 0x65, 0x92, 0xBD,
    0x86, 0xB8, 0xAF, 0x8F, 0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30, 0xDC, 0x5F, 0x5E, 0xC5, 0x0B, 0x1A,
    0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47, 0x5D, 0x3D, 0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D,
    0x8B, 0x0D, 0x9A, 0x66, 0xFB, 0xCC, 0xB0, 0x2D, 0x74, 0x12, 0x2B, 0x20, 0xF0, 0xB1, 0x84, 0x99,
    0xDF, 0x4C, 0xCB, 0xC2, 0x34, 0x7E, 0x76, 0x05, 0x6D, 0xB7, 0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7,
    0x14, 0x58, 0x3A, 0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16, 0x53, 0x18, 0xF2, 0x22,
    0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24, 0x08, 0xE8, 0xA8, 0x60, 0xFC, 0x69, 0x50,
    0xAA, 0xD0, 0xA0, 0x7D, 0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95, 0xE0, 0xFF, 0x64, 0xD2,
    0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03, 0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94,
    0x87, 0x5C, 0x83, 0x02, 0xCD, 0x4A, 0x90, 0x33, 0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2,
    0x52, 0x9B, 0xD8, 0x26, 0xC8, 0x37, 0xC6, 0x3B, 0x81, 0x96, 0x6F, 0x4B, 0x13, 0xBE, 0x63, 0x2E,
    0xE9, 0x79, 0xA7, 0x8C, 0x9F, 0x6E, 0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59,
    0x78, 0x98, 0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA, 0xD4, 0x25, 0xAB, 0x42, 0x88, 0xA2, 0x8D, 0xFA,
    0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC, 0x0A, 0x36, 0x49, 0x2A, 0x68, 0x3C, 0x38, 0xF1, 0xA4,
    0x40, 0x28, 0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4, 0x77, 0xC7, 0x80, 0x9E,
]

assert SBOX1[0x3d] == 86

SBOX2 = [rotl8(x, 1) for x in SBOX1]
SBOX3 = [rotr8(x, 1) for x in SBOX1]
SBOX4 = [SBOX1[rotl8(x, 1)] for x in range(0x100)]

_F_SBOX_SELECT = [
    SBOX1,
    SBOX2,
    SBOX3,
    SBOX4,
    SBOX2,
    SBOX3,
    SBOX4,
    SBOX1,
]


class CamelliaKey(NamedTuple):
    ks: List[int]
    kw: List[int]


def F(F_IN: int, KE: int):
    t1, t2, t3, t4, t5, t6, t7, t8 = (
        SBOX[I] for SBOX, I in zip(_F_SBOX_SELECT, (F_IN ^ KE).to_bytes(8, 'big'))
    )
    return int.from_bytes((
        t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8,
        t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8,
        t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8,
        t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7,
        t1 ^ t2 ^ t6 ^ t7 ^ t8,
        t2 ^ t3 ^ t5 ^ t7 ^ t8,
        t3 ^ t4 ^ t5 ^ t6 ^ t8,
        t1 ^ t4 ^ t5 ^ t6 ^ t7), 'big')


def FL_INV(y: int, k: int) -> int:
    assert y.bit_length() <= 64
    assert k.bit_length() <= 64
    y1 = y >> 32
    y2 = y & M32
    k1 = k >> 32
    k2 = k & M32
    y1 = y1 ^ (y2 | k2)
    yr = y1 & k1
    yr = (yr >> 31) | ((yr & 0x7FFFFFFF) << 1)
    return (y1 << 32) | (y2 ^ yr)


def FL_FWD(x: int, k: int) -> int:
    assert x.bit_length() <= 64
    assert k.bit_length() <= 64
    x1 = x >> 32
    x2 = x & M32
    k1 = k >> 32
    k2 = k & M32
    xr = x1 & k1
    xr = (xr >> 31) | ((xr & 0x7FFFFFFF) << 1)
    x2 = x2 ^ xr
    x1 = x1 ^ (x2 | k2)
    return (x1 << 32) | x2


class Camellia(BlockCipher):

    _key_data: CamelliaKey

    block_size = 0x10
    valid_key_sizes = frozenset((0x10, 0x18, 0x20))

    def block_decrypt(self, block) -> BufferType:
        return self._feistel(block, True)

    def block_encrypt(self, block) -> BufferType:
        return self._feistel(block, False)

    def _feistel(self, block, reverse: bool):
        key = self.key
        rounds, remainder = divmod(len(key.ks) + 2, 8)
        assert not remainder
        if reverse:
            W3, W4, W1, W2 = key.kw
        else:
            W1, W2, W3, W4 = key.kw
        key = reversed(key.ks) if reverse else iter(key.ks)
        D1, D2 = unpack('>QQ', block)
        D1 ^= W1
        D2 ^= W2
        for r in range(rounds):
            if r > 0:
                D1 = FL_FWD(D1, next(key))
                D2 = FL_INV(D2, next(key))
            for _ in range(3):
                D2 ^= F(D1, next(key))
                D1 ^= F(D2, next(key))
        D2 ^= W3
        D1 ^= W4
        return ((D2 << 64) | D1).to_bytes(0x10, 'big')

    @property
    def key(self):
        return self._key_data

    @key.setter
    def key(self, key):
        padded_key = key + bytearray(-len(key) % 0x20)

        KL = int.from_bytes(padded_key[:0x10], 'big')
        KR = int.from_bytes(padded_key[0x10:], 'big')

        if len(key) == 0x18:
            KR |= (KR >> 64) ^ 0xFFFFFFFFFFFFFFFF

        DD = KL ^ KR
        D1 = DD >> 64
        D2 = DD & M64
        D2 ^= F(D1, SIGMA1)
        D1 ^= F(D2, SIGMA2)
        D1 ^= (KL >> 64)
        D2 ^= (KL & M64)
        D2 ^= F(D1, SIGMA3)
        D1 ^= F(D2, SIGMA4)
        KA = (D1 << 64) | D2
        D1 = (KA ^ KR) >> 64
        D2 = (KA ^ KR) & M64
        D2 ^= F(D1, SIGMA5)
        D1 ^= F(D2, SIGMA6)
        KB = (D1 << 64) | D2

        ks = []
        kw = []

        def add_key_part(key_list: List[int], key_part: int) -> None:
            key_list.append(key_part >> 64)
            key_list.append(key_part & M64)

        if len(key) == 0x10:
            add_key_part(kw, rotl128(KL, 0x00))  # kw1, kw2
            add_key_part(ks, rotl128(KA, 0x00))  # k01, k02
            add_key_part(ks, rotl128(KL, 0x0F))  # k03, k04
            add_key_part(ks, rotl128(KA, 0x0F))  # k05, k06
            add_key_part(ks, rotl128(KA, 0x1E))  # ke1, ke2
            add_key_part(ks, rotl128(KL, 0x2D))  # k07, k08
            ks.append(rotl128(KA, 0x2D) >> 64)   # k09
            ks.append(rotl128(KL, 0x3C) & M64)   # k10
            add_key_part(ks, rotl128(KA, 0x3C))  # k11, k12
            add_key_part(ks, rotl128(KL, 0x4D))  # ke3, ke4
            add_key_part(ks, rotl128(KL, 0x5E))  # k13, k14
            add_key_part(ks, rotl128(KA, 0x5E))  # k15, k16
            add_key_part(ks, rotl128(KL, 0x6F))  # k16, k18
            add_key_part(kw, rotl128(KA, 0x6F))  # kw3, kw4
        else:
            add_key_part(kw, rotl128(KL, 0x00))  # kw1, kw2
            add_key_part(ks, rotl128(KB, 0x00))  # k01, k02
            add_key_part(ks, rotl128(KR, 0x0F))  # k03, k04
            add_key_part(ks, rotl128(KA, 0x0F))  # k05, k06
            add_key_part(ks, rotl128(KR, 0x1E))  # ke1, ke2
            add_key_part(ks, rotl128(KB, 0x1E))  # k07, k08
            add_key_part(ks, rotl128(KL, 0x2D))  # k09, k10
            add_key_part(ks, rotl128(KA, 0x2D))  # k11, k12
            add_key_part(ks, rotl128(KL, 0x3C))  # ke3, ke4
            add_key_part(ks, rotl128(KR, 0x3C))  # k13, k14
            add_key_part(ks, rotl128(KB, 0x3C))  # k15, k16
            add_key_part(ks, rotl128(KL, 0x4D))  # k17, k18
            add_key_part(ks, rotl128(KA, 0x4D))  # ke5, ke6
            add_key_part(ks, rotl128(KR, 0x5E))  # k19, k20
            add_key_part(ks, rotl128(KA, 0x5E))  # k21, k22
            add_key_part(ks, rotl128(KL, 0x6F))  # k23, k24
            add_key_part(kw, rotl128(KB, 0x6F))  # kw3, kw4

        self._key_data = CamelliaKey(ks, kw)


class camellia(StandardBlockCipherUnit, cipher=BlockCipherFactory(Camellia)):
    """
    Camellia encryption and decryption.
    """
    pass
