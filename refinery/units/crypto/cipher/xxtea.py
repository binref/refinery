#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import ByteString
from refinery.units.crypto.cipher import BlockCipherUnitBase
from refinery.lib import chunks


class xxtea(BlockCipherUnitBase):
    """
    XXTEA encryption and decryption.
    """
    def __init__(self, key, padding=None, raw=False):
        ...

    @property
    def _key(self):
        key = self.args.key
        if len(key) != 0x10:
            raise ValueError(F'Key length of {len(key)} bytes is invalid; XXTEA only supports 16 byte keys')
        return chunks.unpack(key, 4)

    def _unpack(self, data):
        if len(data) % 4:
            raise ValueError('The input data is not aligned to a multiple of 4 bytes.')
        return chunks.unpack(data, 4)

    def encrypt(self, v: ByteString) -> ByteString:
        if not v:
            return v
        key = self._key
        v = list(self._unpack(v))
        n = len(v)
        s = 0
        r = 6 + 52 // n
        z = v[n - 1]
        for _ in range(r):
            s = s + 0x9E3779B9 & 0xFFFFFFFF
            e = (s >> 2) & 3
            for p in range(n):
                y = v[(p + 1) % n]
                k = (p & 3) ^ e
                x = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (s ^ y) + (key[k] ^ z)
                z = v[p] = v[p] + x & 0xFFFFFFFF
        return chunks.pack(v, 4)

    def decrypt(self, v: ByteString) -> ByteString:
        key = self._key
        v = self._unpack(v)
        n = len(v)
        r = 6 + 52 // n
        s = r * 0x9E3779B9 & 0xFFFFFFFF
        y = v[0]
        for _ in range(r):
            e = (s >> 2) & 3
            for p in range(n - 1, -1, -1):
                z = v[(p - 1) % n]
                k = (p & 3) ^ e
                x = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (s ^ y) + (key[k] ^ z)
                y = v[p] = v[p] - x & 0xFFFFFFFF
            s = s - 0x9E3779B9 & 0xFFFFFFFF
        return chunks.pack(v, 4)
