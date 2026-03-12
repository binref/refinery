"""
Maru hash implementation; it matches the C implementation found in Donut.
"""
from __future__ import annotations

import struct

from refinery.lib.crypto.speck import (
    speck_encrypt32,
    speck_key_schedule_064_128,
)

MARU_MAX_STR = 64
MARU_BLK_LEN = 16
MARU_HASH_LEN = 8


def swap_dwords(value: int) -> int:
    return (value & 0xFFFFFFFF) << 32 | (value & 0xFFFFFFFF00000000) >> 32


def speck_operation(v: bytes, m: bytes) -> int:
    rk = speck_key_schedule_064_128(m)
    h_bytes = speck_encrypt32(v, rk, 27)
    h_int = int.from_bytes(h_bytes, "little")
    return swap_dwords(h_int)


def maru32(value: bytes, seed: int) -> int:
    m = bytearray(MARU_BLK_LEN)
    h = seed
    input_length = len(value)
    idx = 0
    length = 0
    end = False
    while not end:
        if length == input_length or length == MARU_MAX_STR:
            m[idx:] = bytes(MARU_BLK_LEN - idx)
            m[idx] = 0x80
            if idx >= MARU_BLK_LEN - 4:
                h_swapped = swap_dwords(h)
                h_bytes = h_swapped.to_bytes(8, "little")
                h ^= speck_operation(h_bytes, bytes(m))
                m[:] = bytes(MARU_BLK_LEN)
            struct.pack_into('<I', m, MARU_BLK_LEN - 4, length * 8)
            idx = MARU_BLK_LEN
            end = True
        else:
            m[idx] = value[length]
            length += 1
            idx += 1
        if idx == MARU_BLK_LEN:
            h_swapped = swap_dwords(h)
            h_bytes = h_swapped.to_bytes(8, "little")
            h ^= speck_operation(h_bytes, bytes(m))
            idx = 0
    return h


def maru32digest(value: bytes, seed: int) -> bytes:
    return maru32(value, seed).to_bytes(8, 'big')
