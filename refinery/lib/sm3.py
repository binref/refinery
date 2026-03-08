"""
Pure-Python implementation of the SM3 cryptographic hash function as specified in GM/T 0004-2012.
"""
from __future__ import annotations

from refinery.lib.crypto import rotl32

import struct

_IV = (
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
)

_T = [0x79CC4519] * 16 + [0x7A879D8A] * 48


def _ff(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _gg(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (~x & 0xFFFFFFFF & z)


def _p0(x: int) -> int:
    return x ^ rotl32(x, 9) ^ rotl32(x, 17)


def _p1(x: int) -> int:
    return x ^ rotl32(x, 15) ^ rotl32(x, 23)


def _cf(v: list[int], block: bytes):
    w = list(struct.unpack('>16I', block))
    for j in range(16, 68):
        w.append(_p1(w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15)) ^ rotl32(w[j - 13], 7) ^ w[j - 6])
    w1 = [w[j] ^ w[j + 4] for j in range(64)]

    a, b, c, d, e, f, g, h = v

    for j in range(64):
        ss1 = rotl32((rotl32(a, 12) + e + rotl32(_T[j], j % 32)) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ rotl32(a, 12)
        tt1 = (_ff(j, a, b, c) + d + ss2 + w1[j]) & 0xFFFFFFFF
        tt2 = (_gg(j, e, f, g) + h + ss1 + w[j]) & 0xFFFFFFFF
        d = c
        c = rotl32(b, 9)
        b = a
        a = tt1
        h = g
        g = rotl32(f, 19)
        f = e
        e = _p0(tt2)

    for i, x in enumerate((a, b, c, d, e, f, g, h)):
        v[i] ^= x


def sm3_digest(data: bytes | bytearray | memoryview) -> bytes:
    """
    Compute the SM3 hash of the input data.
    """
    data = bytearray(data)
    length = len(data)
    bit_length = length * 8

    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0x00)
    data.extend(struct.pack('>Q', bit_length))

    v: list[int] = list(_IV)
    for i in range(0, len(data), 64):
        _cf(v, bytes(data[i:i + 64]))

    return struct.pack('>8I', *v)
