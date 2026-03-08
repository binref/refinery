from __future__ import annotations

from typing import ClassVar

from refinery.lib.crypto import (
    BlockCipher,
    BlockCipherFactory,
    BufferType,
    CipherInterface,
    CipherMode,
)
from refinery.lib.simon import (
    simon_decrypt16,
    simon_decrypt24,
    simon_decrypt32,
    simon_decrypt48,
    simon_decrypt64,
    simon_encrypt16,
    simon_encrypt24,
    simon_encrypt32,
    simon_encrypt48,
    simon_encrypt64,
    simon_key_schedule_032_064,
    simon_key_schedule_048_072,
    simon_key_schedule_048_096,
    simon_key_schedule_064_096,
    simon_key_schedule_064_128,
    simon_key_schedule_096_096,
    simon_key_schedule_096_144,
    simon_key_schedule_128_128,
    simon_key_schedule_128_192,
    simon_key_schedule_128_256,
)
from refinery.lib.types import Param
from refinery.units.crypto.cipher import (
    Arg,
    StandardBlockCipherUnit,
)

_DISPATCH = {
    (0x04, 0x08): simon_key_schedule_032_064,
    (0x06, 0x09): simon_key_schedule_048_072,
    (0x06, 0x0C): simon_key_schedule_048_096,
    (0x08, 0x0C): simon_key_schedule_064_096,
    (0x08, 0x10): simon_key_schedule_064_128,
    (0x0C, 0x0C): simon_key_schedule_096_096,
    (0x0C, 0x12): simon_key_schedule_096_144,
    (0x10, 0x10): simon_key_schedule_128_128,
    (0x10, 0x18): simon_key_schedule_128_192,
    (0x10, 0x20): simon_key_schedule_128_256,
}


class Simon(BlockCipher):

    block_size: int
    key_size = frozenset((8, 9, 12, 16, 18, 24, 32))

    _round_keys: list[int]
    _rounds: int

    _ROUND_BY_BLOCK_AND_KEY_SIZE: ClassVar[dict[int, dict[int, int]]] = {
        0x04: {8: 32},
        0x06: {9: 36, 12: 36},
        0x08: {12: 42, 16: 44},
        0x0C: {12: 52, 18: 54},
        0x10: {16: 68, 24: 69, 32: 72},
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
        try:
            schedule = _DISPATCH[block_size, key_length]
        except KeyError:
            possible_values = ', '.join(F'{b}/{n}' for b, n in _DISPATCH)
            raise ValueError(
                F'Invalid block size ({block_size}) and key length ({key_length}) combination. '
                F'Choose from the following combinations: {possible_values}.')
        else:
            self._round_keys = schedule(key)

    def __init__(self, key: BufferType, mode: CipherMode | None, block_size: int = 16):
        self.block_size = block_size
        super().__init__(key, mode)

    def block_decrypt(self, data) -> BufferType:
        block_size = self.block_size
        if block_size == 4:
            return simon_decrypt16(data, self._round_keys, self._rounds)
        elif block_size == 6:
            return simon_decrypt24(data, self._round_keys, self._rounds)
        elif block_size == 8:
            return simon_decrypt32(data, self._round_keys, self._rounds)
        elif block_size == 12:
            return simon_decrypt48(data, self._round_keys, self._rounds)
        else:
            return simon_decrypt64(data, self._round_keys, self._rounds)

    def block_encrypt(self, data) -> BufferType:
        block_size = self.block_size
        if block_size == 4:
            return simon_encrypt16(data, self._round_keys, self._rounds)
        elif block_size == 6:
            return simon_encrypt24(data, self._round_keys, self._rounds)
        elif block_size == 8:
            return simon_encrypt32(data, self._round_keys, self._rounds)
        elif block_size == 12:
            return simon_encrypt48(data, self._round_keys, self._rounds)
        else:
            return simon_encrypt64(data, self._round_keys, self._rounds)


class simon(StandardBlockCipherUnit, cipher=BlockCipherFactory(Simon)):
    """
    SIMON encryption and decryption. SIMON is a family of lightweight block ciphers designed by
    the NSA, published in 2013 and optimized for hardware implementations. The cipher uses a
    balanced Feistel network with a round function based on bitwise AND, circular left shifts,
    and XOR. This unit supports all 10 SIMON variants: SIMON 32/64 (4-byte block), SIMON 48/72
    and SIMON 48/96 (6-byte block), SIMON 64/96 and SIMON 64/128 (8-byte block), SIMON 96/96
    and SIMON 96/144 (12-byte block), and SIMON 128/128, SIMON 128/192, SIMON 128/256 (16-byte
    block). SIMON is often found in IoT devices and embedded systems. See also
    `refinery.units.crypto.cipher.speck`.
    """
    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False,
        block_size: Param[int, Arg.Number('-b',
            help='Cipher block size, default is {default}. Valid choices are 4, 6, 8, 12, and 16.')] = 16,
        **more
    ):
        return super().__init__(
            key, iv=iv, padding=padding, mode=mode, raw=raw, block_size=block_size, **more)

    @property
    def block_size(self):
        return self.args.block_size

    def _new_cipher(self, **optionals) -> CipherInterface:
        return super()._new_cipher(block_size=self.args.block_size, **optionals)
