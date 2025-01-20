#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import List, Optional

from refinery.lib.speck import (
    speck_encrypt32,
    speck_encrypt64,
    speck_decrypt32,
    speck_decrypt64,
    Speck6496KeySchedule,
    Speck64128KeySchedule,
    Speck128128KeySchedule,
    Speck128192KeySchedule,
    Speck128256KeySchedule,
)

from refinery.units.crypto.cipher import (
    Arg,
    StandardBlockCipherUnit,
)
from refinery.lib.crypto import (
    BlockCipher,
    BlockCipherFactory,
    BufferType,
    CipherInterface,
    CipherMode,
)


class Speck(BlockCipher):

    block_size: int
    key_size = frozenset((12, 16, 24, 32))

    _round_keys: List[int]
    _rounds: int

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key: bytes):
        self._key = key
        block_size = self.block_size
        key_length = len(key)
        if block_size == 16:
            if key_length == 16:
                self._round_keys = Speck128128KeySchedule(key)
                self._rounds = 32
            elif key_length == 24:
                self._round_keys = Speck128192KeySchedule(key)
                self._rounds = 33
            elif key_length == 32:
                self._round_keys = Speck128256KeySchedule(key)
                self._rounds = 34
        elif block_size == 8:
            if key_length == 12:
                self._round_keys = Speck6496KeySchedule(key)
                self._rounds = 26
            elif key_length == 16:
                self._round_keys = Speck64128KeySchedule(key)
                self._rounds = 27

    def __init__(self, key: BufferType, mode: Optional[CipherMode], block_size: int = 16):
        self.block_size = block_size
        super().__init__(key, mode)

    def block_decrypt(self, block) -> BufferType:
        block_size = self.block_size
        if block_size == 16:
            return speck_decrypt64(block, self._round_keys, self._rounds)
        else:
            return speck_decrypt32(block, self._round_keys, self._rounds)

    def block_encrypt(self, block) -> BufferType:
        block_size = self.block_size
        if block_size == 16:
            return speck_encrypt64(block, self._round_keys, self._rounds)
        else:
            return speck_encrypt32(block, self._round_keys, self._rounds)

class speck(StandardBlockCipherUnit, cipher=BlockCipherFactory(Speck)):
    """
    SPECK encryption and decryption. It supports block sizes of 8 and 16 bytes.
    """
    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False,
        block_size: Arg.Number('-b', help='Cipher block size, default is {default}. Valid choices are 8 and 16.') = 16,
        **more
    ):
        return super().__init__(key, iv, padding=padding, mode=mode, raw=raw, block_size=block_size, **more)

    @property
    def block_size(self):
        return self.args.block_size

    def _new_cipher(self, **optionals) -> CipherInterface:
        return super()._new_cipher(block_size=self.args.block_size, **optionals)
