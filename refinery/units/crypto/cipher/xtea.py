#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Sequence, Tuple
from refinery.units.crypto.cipher.tea import (
    tea_block_operation, TEABase, TEAUnit, BlockCipherFactory
)


class XTEA(TEABase):
    """
    The XTEA cipher.
    """

    @tea_block_operation
    def block_encrypt(key: Sequence[int], block: Sequence[int]) -> Tuple[int, int]:
        carry = 0
        delta = 0x9E3779B9
        v0, v1 = block
        for _ in range(32):
            v0 = v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (carry + key[carry & 3])) & 0xFFFFFFFF
            carry = carry + delta & 0xFFFFFFFF
            shift = carry >> 11
            v1 = v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (carry + key[shift & 3])) & 0xFFFFFFFF
        return (v0, v1)

    @tea_block_operation
    def block_decrypt(key: Sequence[int], block: Sequence[int]) -> Tuple[int, int]:
        delta = 0x9E3779B9
        carry = 0xC6EF3720
        v0, v1 = block
        for _ in range(32):
            shift = carry >> 11
            v1 = v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (carry + key[shift & 3])) & 0xFFFFFFFF
            carry = carry - delta & 0xFFFFFFFF
            v0 = v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (carry + key[carry & 3])) & 0xFFFFFFFF
        return (v0, v1)


class xtea(TEAUnit, cipher=BlockCipherFactory(XTEA)):
    """
    XTEA encryption and decryption.
    """
    pass
