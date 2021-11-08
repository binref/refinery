#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.crypto.cipher import StandardBlockCipherUnit
from refinery.units.crypto.cipher.tea import (
    tea_block_operation, TEABase, BlockCipherFactory
)


class XTEA(TEABase):
    """
    The XTEA cipher.
    """

    @tea_block_operation
    def block_encrypt(v0, v1, *key):
        carry = 0
        delta = 0x9E3779B9
        for _ in range(32):
            v0 = v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (carry + key[carry & 3])) & 0xFFFFFFFF
            carry = carry + delta & 0xFFFFFFFF
            shift = carry >> 11
            v1 = v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (carry + key[shift & 3])) & 0xFFFFFFFF
        return v0, v1

    @tea_block_operation
    def block_decrypt(v0, v1, *key):
        delta = 0x9E3779B9
        carry = 0xC6EF3720
        for _ in range(32):
            shift = carry >> 11
            v1 = v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (carry + key[shift & 3])) & 0xFFFFFFFF
            carry = carry - delta & 0xFFFFFFFF
            v0 = v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (carry + key[carry & 3])) & 0xFFFFFFFF
        return v0, v1


class xtea(StandardBlockCipherUnit, cipher=BlockCipherFactory(XTEA)):
    """
    XTEA encryption and decryption.
    """
    pass
