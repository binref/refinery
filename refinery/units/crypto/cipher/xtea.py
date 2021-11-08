#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import ByteString, Callable, List, Tuple

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import BlockCipher, BlockCipherFactory


class XTEA(BlockCipher):
    """
    XTEA encryption and decryption.
    """
    block_size = 8
    valid_key_sizes = {16}
    derived_key: List[int]

    @property
    def key(self):
        return self.derived_key

    @key.setter
    def key(self, key):
        self.derived_key = [int.from_bytes(key[k:k + 4], 'little') for k in range(0, 16, 4)]

    def block_operation(
        blk: Callable[[int, int, int, int, int, int], Tuple[int, int]]
    ) -> Callable[[XTEA, ByteString], ByteString]:
        def wrapped(self: XTEA, data: ByteString) -> ByteString:
            k0, k1, k2, k3 = self.derived_key
            v0 = int.from_bytes(data[:4], 'little')
            v1 = int.from_bytes(data[4:], 'little')
            v0, v1 = blk(k0, k1, k2, k3, v0, v1)
            return v0.to_bytes(4, 'little') + v1.to_bytes(4, 'little')
        return wrapped

    @block_operation
    def block_encrypt(k0, k1, k2, k3, v0, v1):
        carry = 0
        delta = 0x9E3779B9
        for _ in range(32, 0, -1):
            carry = (carry + delta) & 0xFFFFFFFF
            v0 = v0 + (((v1 << 4) + k0) ^ (v1 + carry) ^ (v1 >> 5) + k1) & 0xFFFFFFFF
            v1 = v1 + (((v0 << 4) + k2) ^ (v0 + carry) ^ (v0 >> 5) + k3) & 0xFFFFFFFF
        return v0, v1

    @block_operation
    def block_decrypt(k0, k1, k2, k3, v0, v1):
        carry = 0xC6EF3720
        delta = 0x9E3779B9
        for _ in range(32, 0, -1):
            v1 = v1 - (((v0 << 4) + k2) ^ (v0 + carry) ^ (v0 >> 5) + k3) & 0xFFFFFFFF
            v0 = v0 - (((v1 << 4) + k0) ^ (v1 + carry) ^ (v1 >> 5) + k1) & 0xFFFFFFFF
            carry = (carry - delta) & 0xFFFFFFFF
        return v0, v1

    del block_operation


class xtea(StandardBlockCipherUnit, cipher=BlockCipherFactory(XTEA)):
    pass
