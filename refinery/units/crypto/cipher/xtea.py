#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct

from . import BlockCipherUnitBase


class xtea(BlockCipherUnitBase):
    """
    XTEA encryption and decryption.
    """
    blocksize = 16
    key_sizes = 16

    def __init__(self, key, padding=None):
        super().__init__(key=key, padding=padding)

    @property
    def key(self):
        return struct.unpack('4I', self.args.key)

    def encrypt(self, data):
        it = iter(self._load32(data))
        return self._stor64(self._encrypt_block(y, z, *self.key) for y, z in zip(it, it))

    def decrypt(self, data):
        it = iter(self._load32(data))
        return self._stor64(self._decrypt_block(y, z, *self.key) for y, z in zip(it, it))

    @staticmethod
    def _encrypt_block(y, z, k1, k2, k3, k4):
        sum_t = 0
        delta = 0x9E3779B9
        for _ in range(32, 0, -1):
            sum_t = (sum_t + delta) & 0xFFFFFFFF
            y = y + ((z << 4) + k1 ^ z + sum_t ^ (z >> 5) + k2) & 0xFFFFFFFF
            z = z + ((y << 4) + k3 ^ y + sum_t ^ (y >> 5) + k4) & 0xFFFFFFFF
        return y + (z << 0x20)

    @staticmethod
    def _decrypt_block(y, z, k1, k2, k3, k4):
        sum_t = 0xC6EF3720
        delta = 0x9E3779B9
        for _ in range(32, 0, -1):
            z = z - ((y << 4) + k3 ^ y + sum_t ^ (y >> 5) + k4) & 0xFFFFFFFF
            y = y - ((z << 4) + k1 ^ z + sum_t ^ (z >> 5) + k2) & 0xFFFFFFFF
            sum_t = (sum_t - delta) & 0xFFFFFFFF
        return y + (z << 0x20)

    @staticmethod
    def _load32(vector):
        Q, R = divmod(len(vector), 4)
        if R > 0:
            raise ValueError('Data not padded to a 16 byte boundary.')
        yield from struct.unpack(F'{Q}I', vector)

    @staticmethod
    def _stor64(vector):
        vector = tuple(vector)
        return struct.pack(F'{len(vector)}Q', *vector)
