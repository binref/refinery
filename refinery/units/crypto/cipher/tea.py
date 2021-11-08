#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import ByteString, Callable, List, Tuple

from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.lib.crypto import BlockCipher, BlockCipherFactory


def tea_block_operation(
    blk: Callable[[int, int, int, int, int, int], Tuple[int, int]]
) -> Callable[[TEA, ByteString], ByteString]:
    def wrapped(self: TEA, data: ByteString) -> ByteString:
        v0, v1 = blk(
            int.from_bytes(data[:4], 'little'),
            int.from_bytes(data[4:], 'little'),
            *self.derived_key
        )
        return v0.to_bytes(4, 'little') + v1.to_bytes(4, 'little')
    return wrapped


class TEABase(BlockCipher):

    block_size = 8
    valid_key_sizes = {16}
    derived_key: List[int]

    @property
    def key(self):
        return self.derived_key

    @key.setter
    def key(self, key):
        self.derived_key = [int.from_bytes(key[k:k + 4], 'little') for k in range(0, 16, 4)]


class TEA(TEABase):
    """
    The TEA cipher.
    """
    @tea_block_operation
    def block_encrypt(v0, v1, k0, k1, k2, k3):
        carry = 0
        delta = 0x9E3779B9
        for _ in range(32):
            carry = (carry + delta) & 0xFFFFFFFF
            v0 = v0 + (((v1 << 4) + k0) ^ (v1 + carry) ^ (v1 >> 5) + k1) & 0xFFFFFFFF
            v1 = v1 + (((v0 << 4) + k2) ^ (v0 + carry) ^ (v0 >> 5) + k3) & 0xFFFFFFFF
        return v0, v1

    @tea_block_operation
    def block_decrypt(v0, v1, k0, k1, k2, k3):
        carry = 0xC6EF3720
        delta = 0x9E3779B9
        for _ in range(32):
            v1 = v1 - (((v0 << 4) + k2) ^ (v0 + carry) ^ (v0 >> 5) + k3) & 0xFFFFFFFF
            v0 = v0 - (((v1 << 4) + k0) ^ (v1 + carry) ^ (v1 >> 5) + k1) & 0xFFFFFFFF
            carry = (carry - delta) & 0xFFFFFFFF
        return v0, v1


class tea(StandardBlockCipherUnit, cipher=BlockCipherFactory(TEA)):
    """
    TEA encryption and decryption.
    """
    pass
