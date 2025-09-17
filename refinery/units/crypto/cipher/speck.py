from __future__ import annotations

from typing import ClassVar

from refinery.lib.crypto import (
    BlockCipher,
    BlockCipherFactory,
    BufferType,
    CipherInterface,
    CipherMode,
)
from refinery.lib.speck import (
    Speck6496KeySchedule,
    Speck64128KeySchedule,
    Speck128128KeySchedule,
    Speck128192KeySchedule,
    Speck128256KeySchedule,
    speck_decrypt32,
    speck_decrypt64,
    speck_encrypt32,
    speck_encrypt64,
)
from refinery.lib.types import Param
from refinery.units.crypto.cipher import (
    Arg,
    StandardBlockCipherUnit,
)


class Speck(BlockCipher):

    block_size: int
    key_size = frozenset((12, 16, 24, 32))

    _round_keys: list[int]
    _rounds: int

    _ROUND_BY_BLOCK_AND_KEY_SIZE: ClassVar[dict[int, dict[int, int]]] = {
        8: {12: 26, 16: 27},
        16: {16: 32, 24: 33, 32: 34}
    }

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key: bytes):
        self._key = key
        block_size = self.block_size
        key_length = len(key)
        rounds = self._ROUND_BY_BLOCK_AND_KEY_SIZE[block_size][key_length]
        self._rounds = rounds
        if block_size == 16:
            if key_length == 16:
                self._round_keys = Speck128128KeySchedule(key)
            elif key_length == 24:
                self._round_keys = Speck128192KeySchedule(key)
            elif key_length == 32:
                self._round_keys = Speck128256KeySchedule(key)
        elif block_size == 8:
            if key_length == 12:
                self._round_keys = Speck6496KeySchedule(key)
            elif key_length == 16:
                self._round_keys = Speck64128KeySchedule(key)

    def __init__(self, key: BufferType, mode: CipherMode | None, block_size: int = 16):
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
        block_size: Param[int, Arg.Number('-b', help='Cipher block size, default is {default}. Valid choices are 8 and 16.')] = 16,
        **more
    ):
        return super().__init__(key, iv=iv, padding=padding, mode=mode, raw=raw, block_size=block_size, **more)

    @property
    def block_size(self):
        return self.args.block_size

    def _new_cipher(self, **optionals) -> CipherInterface:
        return super()._new_cipher(block_size=self.args.block_size, **optionals)
