#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import List, Optional

from refinery.units.crypto.cipher import (
    Arg,
    StandardBlockCipherUnit,
)
from refinery.lib.serpent import (
    make_subkeys,
    serpent_encrypt,
    serpent_decrypt,
)
from refinery.lib.crypto import (
    BlockCipher,
    BlockCipherFactory,
    BufferType,
    CipherMode,
    CipherInterface,
)


class Serpent(BlockCipher):

    _key_data: List[int]
    _key_derivation: List[int]

    block_size = 0x10
    key_size = frozenset(range(4, 0x101, 4))

    def __init__(self, key: BufferType, mode: Optional[CipherMode], swap: bool = True):
        super().__init__(key, mode)
        self.swap = swap

    def block_decrypt(self, block) -> BufferType:
        return serpent_decrypt(block, self.key, self.swap)

    def block_encrypt(self, block) -> BufferType:
        return serpent_encrypt(block, self.key, self.swap)

    @property
    def key(self):
        try:
            return self._key_derivation
        except AttributeError:
            kd = make_subkeys(self._key_data)
            self._key_derivation = kd
            return kd

    @key.setter
    def key(self, key):
        self._key_data = key


class serpent(StandardBlockCipherUnit, cipher=BlockCipherFactory(Serpent)):
    """
    Serpent encryption and decryption. Some Serpent implementations read the bytes of each block
    in one direction, some in the other. When decryption results with this unit do not yield the
    expected result, try using the `--swap` (or `-s`) option to swap the bytes in each block.
    Furthermore, it is sometimes necessary to swap the bytes of the input key, which can be done
    by prefixing the input key by the multibin handler `snip[::-1]`.
    """
    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False,
        swap: Arg.Switch('-s', help='Read the bytes in each block in reverse order.') = False
    ):
        super().__init__(key, iv, padding=padding, mode=mode, raw=raw, swap=swap)

    def _new_cipher(self, **optionals) -> CipherInterface:
        instance: Serpent = super()._new_cipher()
        instance.swap = self.args.swap
        return instance
