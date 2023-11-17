#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import ByteString, Callable, List, Iterable, Sequence, Optional

from refinery.units.crypto.cipher import StandardBlockCipherUnit, Arg
from refinery.lib.crypto import BlockCipher, BlockCipherFactory, CipherInterface, BufferType, CipherMode
from refinery.lib.chunks import pack, unpack


def tea_block_operation(
    blk: Callable[[Sequence[int], Sequence[int]], Iterable[int]]
) -> Callable[[TEABase, ByteString], ByteString]:
    def wrapped(self: TEABase, data: ByteString) -> ByteString:
        be = self.big_endian
        blocks = list(unpack(data, 4, be))
        blocks = blk(self.derived_key, blocks)
        return pack(blocks, 4, be)
    return wrapped


class TEABase(BlockCipher):

    block_size = 8
    key_size = {16}
    derived_key: List[int]
    big_endian: bool

    def __init__(self, key: BufferType, mode: Optional[CipherMode], big_endian: bool = False):
        self.big_endian = big_endian
        super().__init__(key, mode)

    @property
    def key(self):
        return self.derived_key

    @key.setter
    def key(self, key):
        self.derived_key = unpack(key, 4, self.big_endian)


class TEA(TEABase):
    """
    The TEA cipher.
    """

    @tea_block_operation
    def block_encrypt(key: Sequence[int], block: Sequence[int]):
        k0, k1, k2, k3 = key
        v0, v1 = block
        carry = 0
        delta = 0x9E3779B9
        for _ in range(32):
            carry = (carry + delta) & 0xFFFFFFFF
            v0 = v0 + (((v1 << 4) + k0) ^ (v1 + carry) ^ (v1 >> 5) + k1) & 0xFFFFFFFF
            v1 = v1 + (((v0 << 4) + k2) ^ (v0 + carry) ^ (v0 >> 5) + k3) & 0xFFFFFFFF
        return (v0, v1)

    @tea_block_operation
    def block_decrypt(key: Sequence[int], block: Sequence[int]):
        k0, k1, k2, k3 = key
        v0, v1 = block
        carry = 0xC6EF3720
        delta = 0x9E3779B9
        for _ in range(32):
            v1 = v1 - (((v0 << 4) + k2) ^ (v0 + carry) ^ (v0 >> 5) + k3) & 0xFFFFFFFF
            v0 = v0 - (((v1 << 4) + k0) ^ (v1 + carry) ^ (v1 >> 5) + k1) & 0xFFFFFFFF
            carry = (carry - delta) & 0xFFFFFFFF
        return (v0, v1)


class TEAUnit(StandardBlockCipherUnit):
    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False,
        swap: Arg.Switch('-s', help='Decode blocks as big endian rather than little endian.') = False,
        **more
    ):
        super().__init__(key, iv, padding=padding, mode=mode, raw=raw, swap=swap, **more)

    @property
    def block_size(self):
        return 8

    def _new_cipher(self, **optionals) -> CipherInterface:
        return super()._new_cipher(big_endian=self.args.swap, **optionals)


class tea(TEAUnit, cipher=BlockCipherFactory(TEA)):
    """
    TEA encryption and decryption.
    """
