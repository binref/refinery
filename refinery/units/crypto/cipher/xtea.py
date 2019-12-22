#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct

from . import CipherUnit


class xtea(CipherUnit):
    """
    XTEA encryption and decryption.
    """

    __blocksize__ = 16
    __key_sizes__ = 16

    def encrypt(self, data):
        blocks = iter(self._load32(data))
        key = struct.unpack('LLLL', self.key)
        return self._stor64(self._encrypt_block(*bp, *key) for bp in zip(blocks, blocks))

    def decrypt(self, data):
        blocks = iter(self._load32(data))
        key = struct.unpack('LLLL', self.key)
        return self._stor64(self._decrypt_block(*z, *key) for z in zip(blocks, blocks))

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
        return struct.unpack('L' * (len(vector) // 4), vector)

    @staticmethod
    def _stor64(vector):
        vector = tuple(vector)
        return struct.pack('Q' * len(vector), *vector)
