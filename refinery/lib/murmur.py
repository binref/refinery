#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pymmh3 was originally written by Fredrik Kihlander and enhanced by Swapnil Gusani.
# source: https://github.com/wc-duck/pymmh3
# This file is a modification of their source code.
from struct import unpack


def mmh32(key: bytes, seed=0) -> int:
    key = memoryview(key)

    def fmix(h: int) -> int:
        h ^= h >> 16
        h *= 0x85EBCA6B
        h &= 0xFFFFFFFF
        h ^= h >> 13
        h *= 0xC2B2AE35
        h &= 0xFFFFFFFF
        h ^= h >> 16
        return h

    length = len(key)
    tail_size = length & 3
    tail_index = length - tail_size

    h1 = seed

    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for block_start in range(0, tail_index, 4):
        k1 = int.from_bytes(key[block_start:block_start + 4], 'little', signed=False)
        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1
        h1 = (h1 << 13 | h1 >> 19) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0

    if tail_size >= 3:
        k1 ^= key[tail_index + 2] << 0x10
    if tail_size >= 2:
        k1 ^= key[tail_index + 1] << 0x08
    if tail_size >= 1:
        k1 ^= key[tail_index + 0]

    if tail_size > 0:
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    return fmix(h1 ^ length)


def mmh32digest(key: bytes, seed: int = 0) -> bytes:
    return mmh32(key, seed).to_bytes(4, 'big')


def mmh128x64(key: bytes, seed: int = 0) -> int:
    key = memoryview(key)

    def fmix(k):
        k ^= k >> 33
        k *= 0xFF51AFD7ED558CCD
        k &= 0xFFFFFFFFFFFFFFFF
        k ^= k >> 33
        k *= 0xC4CEB9FE1A85EC53
        k &= 0xFFFFFFFFFFFFFFFF
        k ^= k >> 33
        return k

    length = len(key)
    tail_size = length & 15
    tail_index = length - tail_size

    h1: int = seed
    h2: int = seed

    c1 = 0x87C37B91114253D5
    c2 = 0x4CF5AD432745937F

    for block_start in range(0, tail_index, 16):
        k1, k2 = unpack('<QQ', key[block_start:block_start + 16])

        k1 = (c1 * k1) & 0xFFFFFFFFFFFFFFFF
        k1 = (k1 << 31 | k1 >> 33) & 0xFFFFFFFFFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFFFFFFFFFF
        h1 ^= k1

        h1 = (h1 << 27 | h1 >> 37) & 0xFFFFFFFFFFFFFFFF
        h1 = (h1 + h2) & 0xFFFFFFFFFFFFFFFF
        h1 = (h1 * 5 + 0x52DCE729) & 0xFFFFFFFFFFFFFFFF

        k2 = (c2 * k2) & 0xFFFFFFFFFFFFFFFF
        k2 = (k2 << 33 | k2 >> 31) & 0xFFFFFFFFFFFFFFFF
        k2 = (c1 * k2) & 0xFFFFFFFFFFFFFFFF
        h2 ^= k2

        h2 = (h2 << 31 | h2 >> 33) & 0xFFFFFFFFFFFFFFFF
        h2 = (h1 + h2) & 0xFFFFFFFFFFFFFFFF
        h2 = (h2 * 5 + 0x38495AB5) & 0xFFFFFFFFFFFFFFFF

    k1 = 0
    k2 = 0

    if tail_size >= 0xF:
        k2 ^= key[tail_index + 0xE] << 0x30
    if tail_size >= 0xE:
        k2 ^= key[tail_index + 0xD] << 0x28
    if tail_size >= 0xD:
        k2 ^= key[tail_index + 0xC] << 0x20
    if tail_size >= 0xC:
        k2 ^= key[tail_index + 0xB] << 0x18
    if tail_size >= 0xB:
        k2 ^= key[tail_index + 0xA] << 0x10
    if tail_size >= 0xA:
        k2 ^= key[tail_index + 0x9] << 0x08
    if tail_size >= 0x9:
        k2 ^= key[tail_index + 0x8]

    if tail_size > 8:
        k2 = (k2 * c2) & 0xFFFFFFFFFFFFFFFF
        k2 = (k2 << 33 | k2 >> 31) & 0xFFFFFFFFFFFFFFFF
        k2 = (k2 * c1) & 0xFFFFFFFFFFFFFFFF
        h2 ^= k2

    if tail_size >= 8:
        k1 ^= key[tail_index + 7] << 0x38
    if tail_size >= 7:
        k1 ^= key[tail_index + 6] << 0x30
    if tail_size >= 6:
        k1 ^= key[tail_index + 5] << 0x28
    if tail_size >= 5:
        k1 ^= key[tail_index + 4] << 0x20
    if tail_size >= 4:
        k1 ^= key[tail_index + 3] << 0x18
    if tail_size >= 3:
        k1 ^= key[tail_index + 2] << 0x10
    if tail_size >= 2:
        k1 ^= key[tail_index + 1] << 0x08
    if tail_size >= 1:
        k1 ^= key[tail_index + 0]

    if tail_size > 0:
        k1 = (k1 * c1) & 0xFFFFFFFFFFFFFFFF
        k1 = (k1 << 31 | k1 >> 33) & 0xFFFFFFFFFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFFFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h2 ^= length

    h1 = (h1 + h2) & 0xFFFFFFFFFFFFFFFF
    h2 = (h1 + h2) & 0xFFFFFFFFFFFFFFFF

    h1 = fmix(h1)
    h2 = fmix(h2)

    h1 = (h1 + h2) & 0xFFFFFFFFFFFFFFFF
    h2 = (h1 + h2) & 0xFFFFFFFFFFFFFFFF

    return (h1 << 64 | h2)


def mmh128x32(key: bytes, seed: int = 0) -> int:
    key = memoryview(key)

    def fmix(h: int) -> int:
        h ^= h >> 16
        h *= 0x85EBCA6B
        h &= 0xFFFFFFFF
        h ^= h >> 13
        h *= 0xC2B2AE35
        h &= 0xFFFFFFFF
        h ^= h >> 16
        return h

    length = len(key)
    tail_size = length & 15
    tail_index = length - tail_size

    h1, h2, h3, h4 = seed, seed, seed, seed
    c1 = 0x239B961B
    c2 = 0xAB0E9789
    c3 = 0x38B34AE5
    c4 = 0xA1E38B93

    for block_start in range(0, tail_index, 16):
        k1, k2, k3, k4 = unpack('<LLLL', key[block_start:block_start + 16])

        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (c2 * k1) & 0xFFFFFFFF
        h1 ^= k1

        h1 = (h1 << 19 | h1 >> 13) & 0xFFFFFFFF
        h1 = (h1 + h2) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0x561ccd1b) & 0xFFFFFFFF

        k2 = (c2 * k2) & 0xFFFFFFFF
        k2 = (k2 << 16 | k2 >> 16) & 0xFFFFFFFF
        k2 = (c3 * k2) & 0xFFFFFFFF
        h2 ^= k2

        h2 = (h2 << 17 | h2 >> 15) & 0xFFFFFFFF
        h2 = (h2 + h3) & 0xFFFFFFFF
        h2 = (h2 * 5 + 0x0bcaa747) & 0xFFFFFFFF

        k3 = (c3 * k3) & 0xFFFFFFFF
        k3 = (k3 << 17 | k3 >> 15) & 0xFFFFFFFF
        k3 = (c4 * k3) & 0xFFFFFFFF
        h3 ^= k3

        h3 = (h3 << 15 | h3 >> 17) & 0xFFFFFFFF
        h3 = (h3 + h4) & 0xFFFFFFFF
        h3 = (h3 * 5 + 0x96cd1c35) & 0xFFFFFFFF

        k4 = (c4 * k4) & 0xFFFFFFFF
        k4 = (k4 << 18 | k4 >> 14) & 0xFFFFFFFF
        k4 = (c1 * k4) & 0xFFFFFFFF
        h4 ^= k4

        h4 = (h4 << 13 | h4 >> 19) & 0xFFFFFFFF
        h4 = (h1 + h4) & 0xFFFFFFFF
        h4 = (h4 * 5 + 0x32ac3b17) & 0xFFFFFFFF

    k1 = 0
    k2 = 0
    k3 = 0
    k4 = 0

    if tail_size >= 0xF:
        k4 ^= key[tail_index + 0xE] << 0x10
    if tail_size >= 0xE:
        k4 ^= key[tail_index + 0xD] << 0x08
    if tail_size >= 0xD:
        k4 ^= key[tail_index + 0xC]

    if tail_size > 12:
        k4 = (k4 * c4) & 0xFFFFFFFF
        k4 = (k4 << 18 | k4 >> 14) & 0xFFFFFFFF
        k4 = (k4 * c1) & 0xFFFFFFFF
        h4 ^= k4

    if tail_size >= 0xC:
        k3 ^= key[tail_index + 0xB] << 0x18
    if tail_size >= 0xB:
        k3 ^= key[tail_index + 0xA] << 0x10
    if tail_size >= 0xA:
        k3 ^= key[tail_index + 0x9] << 0x08
    if tail_size >= 0x9:
        k3 ^= key[tail_index + 0x8]

    if tail_size > 8:
        k3 = (k3 * c3) & 0xFFFFFFFF
        k3 = (k3 << 17 | k3 >> 15) & 0xFFFFFFFF
        k3 = (k3 * c4) & 0xFFFFFFFF
        h3 ^= k3

    if tail_size >= 8:
        k2 ^= key[tail_index + 7] << 0x18
    if tail_size >= 7:
        k2 ^= key[tail_index + 6] << 0x10
    if tail_size >= 6:
        k2 ^= key[tail_index + 5] << 0x08
    if tail_size >= 5:
        k2 ^= key[tail_index + 4]

    if tail_size > 4:
        k2 = (k2 * c2) & 0xFFFFFFFF
        k2 = (k2 << 16 | k2 >> 16) & 0xFFFFFFFF
        k2 = (k2 * c3) & 0xFFFFFFFF
        h2 ^= k2

    if tail_size >= 4:
        k1 ^= key[tail_index + 3] << 0x18
    if tail_size >= 3:
        k1 ^= key[tail_index + 2] << 0x10
    if tail_size >= 2:
        k1 ^= key[tail_index + 1] << 0x08
    if tail_size >= 1:
        k1 ^= key[tail_index + 0]

    if tail_size > 0:
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h2 ^= length
    h3 ^= length
    h4 ^= length

    h1 = (h1 + h2) & 0xFFFFFFFF
    h1 = (h1 + h3) & 0xFFFFFFFF
    h1 = (h1 + h4) & 0xFFFFFFFF
    h2 = (h1 + h2) & 0xFFFFFFFF
    h3 = (h1 + h3) & 0xFFFFFFFF
    h4 = (h1 + h4) & 0xFFFFFFFF

    h1 = fmix(h1)
    h2 = fmix(h2)
    h3 = fmix(h3)
    h4 = fmix(h4)

    h1 = (h1 + h2) & 0xFFFFFFFF
    h1 = (h1 + h3) & 0xFFFFFFFF
    h1 = (h1 + h4) & 0xFFFFFFFF
    h2 = (h1 + h2) & 0xFFFFFFFF
    h3 = (h1 + h3) & 0xFFFFFFFF
    h4 = (h1 + h4) & 0xFFFFFFFF

    return (h1 << 96 | h2 << 64 | h3 << 32 | h4)


def mmh128digest64(key: bytes, seed: int = 0) -> bytes:
    return mmh128x64(key, seed).to_bytes(0x10, 'big')


def mmh128digest32(key: bytes, seed: int = 0) -> bytes:
    return mmh128x32(key, seed).to_bytes(0x10, 'big')
