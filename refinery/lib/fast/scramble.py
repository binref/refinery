from __future__ import annotations

import hashlib
import struct


class _PRNG:
    __slots__ = ('_seeded', '_counter', '_buf', '_offset')

    def __init__(self, key: bytes):
        self._seeded = hashlib.sha256(key)
        self._counter = 0
        self._buf = b''
        self._offset = 0

    def _refill(self):
        h = self._seeded.copy()
        h.update(struct.pack('>Q', self._counter))
        self._counter += 1
        self._buf = h.digest()
        self._offset = 0

    def next_u32(self) -> int:
        buf = self._buf
        offset = self._offset
        if offset + 4 > len(buf):
            result = 0
            for shift in (24, 16, 8, 0):
                if self._offset >= len(self._buf):
                    self._refill()
                result |= self._buf[self._offset] << shift
                self._offset += 1
            return result & 0xFFFFFFFF
        self._offset = offset + 4
        return ((buf[offset] << 24) | (buf[offset + 1] << 16)
                | (buf[offset + 2] << 8) | buf[offset + 3])


def _generate_inverse_permutation(seed: bytes) -> bytes:
    prng = _PRNG(seed)
    table = bytearray(range(256))
    for n in range(255, 0, -1):
        threshold = 0xFFFFFFFF - (0xFFFFFFFF % (n + 1))
        while True:
            rand = prng.next_u32()
            if rand <= threshold:
                break
        j = rand % (n + 1)
        table[n], table[j] = table[j], table[n]
    inv = bytearray(256)
    for i, v in enumerate(table):
        inv[v] = i
    return bytes(inv)


def decrypt_round(
    data: bytes | bytearray | memoryview,
    key: bytes | bytearray | memoryview,
    round_idx: int,
) -> bytes:
    result = bytearray(len(data))
    prev = 0
    round_seeded = hashlib.sha256(bytes(key) + b'%c' % round_idx)
    for i, byte in enumerate(data):
        h = round_seeded.copy()
        h.update(str(i).encode())
        inv = _generate_inverse_permutation(h.digest())
        result[i] = inv[byte] ^ prev
        prev = byte
    return bytes(result)
