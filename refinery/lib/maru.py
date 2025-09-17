"""
Maru hash implementation; it matches the C implementation found in Donut.
"""
from __future__ import annotations

from ctypes import (
    Array,
    Union,
    c_uint8,
    c_uint32,
)

from refinery.lib.speck import (
    Speck64128KeySchedule,
    speck_encrypt32,
)

MARU_MAX_STR = 64
MARU_BLK_LEN = 16
MARU_HASH_LEN = 8


class uint8_array(Array):
    _type_ = c_uint8
    _length_ = MARU_BLK_LEN


class uint32_array(Array):
    _type_ = c_uint32
    _length_ = MARU_BLK_LEN // 4


class m_type(Union):
    _fields_ = ("b", uint8_array), ("w", uint32_array)


def swap_dwords(value: int) -> int:
    return (value & 0xFFFFFFFF) << 32 | (value & 0xFFFFFFFF00000000) >> 32


def speck_operation(v: bytearray, m: bytearray) -> int:
    rk = Speck64128KeySchedule(m)
    h_bytes = speck_encrypt32(v, rk, 27)
    h_int = int.from_bytes(h_bytes, "little")
    h_swapped = swap_dwords(h_int)
    return h_swapped


def maru32(value: bytes, seed: int) -> int:
    m = m_type()
    h = seed
    input_length = len(value)
    idx = 0
    length = 0
    end = False
    while not end:
        if length == input_length or length == MARU_MAX_STR:
            m.b[idx:] = (0,) * (MARU_BLK_LEN - idx)
            m.b[idx] = 0x80
            if idx >= MARU_BLK_LEN - 4:
                h_swapped = swap_dwords(h)
                h_bytes = h_swapped.to_bytes(8, "little")
                h ^= speck_operation(h_bytes, bytes(m.b))
                m.b[:] = (0,) * MARU_BLK_LEN
            m.w[(MARU_BLK_LEN // 4) - 1] = length * 8
            idx = MARU_BLK_LEN
            end = True
        else:
            m.b[idx] = value[length]
            length += 1
            idx += 1
        if idx == MARU_BLK_LEN:
            h_swapped = swap_dwords(h)
            h_bytes = h_swapped.to_bytes(8, "little")
            h ^= speck_operation(h_bytes, bytes(m.b))
            idx = 0
    return h


def maru32digest(value: bytes, seed: int) -> bytes:
    return maru32(value, seed).to_bytes(8, 'big')
