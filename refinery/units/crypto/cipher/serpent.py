#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import pack, unpack
from typing import List

from refinery.units.crypto.cipher import StandardBlockCipherUnit

from refinery.lib.crypto import (
    BlockCipher,
    BlockCipherFactory,
    BufferType,
)

from refinery.lib.thirdparty.serpent import (
    serpent_decrypt,
    serpent_encrypt,
    serpent_set_key,
)


class Serpent(BlockCipher):

    _key_data: List[int]

    block_size = 0x10
    valid_key_sizes = frozenset(range(4, 0x20 + 1, 4))

    def block_decrypt(self, block) -> BufferType:
        return pack('<4L', *serpent_decrypt(self._key_data, unpack('<4L', block)))

    def block_encrypt(self, block) -> BufferType:
        return pack('<4L', *serpent_encrypt(self._key_data, unpack('<4L', block)))

    @property
    def key(self):
        return self._key_data

    @key.setter
    def key(self, key):
        block_count = len(key) // 4
        key_word32 = [0] * 32
        key_word32[:block_count] = unpack(F'<{block_count}L', key)
        self._key_data = [0] * 140
        serpent_set_key(self._key_data, key_word32, len(key))


class serpent(StandardBlockCipherUnit, cipher=BlockCipherFactory(Serpent)):
    """
    Serpent encryption and decryption.
    """
    pass
