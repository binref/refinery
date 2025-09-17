from __future__ import annotations

from abc import abstractmethod
from typing import Iterable, Sequence

from refinery.lib.chunks import pack, unpack
from refinery.lib.crypto import (
    BlockCipher,
    BlockCipherFactory,
    BufferType,
    CipherInterface,
    CipherMode,
)
from refinery.lib.types import Param
from refinery.units.crypto.cipher import Arg, StandardBlockCipherUnit


class TEABase(BlockCipher):

    block_size = 8
    key_size = {16}
    derived_key: list[int]
    big_endian: bool

    def __init__(
        self,
        key: BufferType, mode: CipherMode | None,
        big_endian: bool = False
    ):
        self.big_endian = big_endian
        super().__init__(key, mode)

    @property
    def key(self):
        return self.derived_key

    @key.setter
    def key(self, key):
        self.derived_key = unpack(key, 4, self.big_endian)

    @abstractmethod
    def tea_encrypt(self, key: Sequence[int], block: Iterable[int]):
        pass

    def block_encrypt(self, data):
        be = self.big_endian
        blocks = list(unpack(data, 4, be))
        blocks = self.tea_encrypt(self.derived_key, blocks)
        return pack(blocks, 4, be)

    @abstractmethod
    def tea_decrypt(self, key: Sequence[int], block: Iterable[int]):
        pass

    def block_decrypt(self, data):
        be = self.big_endian
        blocks = list(unpack(data, 4, be))
        blocks = self.tea_decrypt(self.derived_key, blocks)
        return pack(blocks, 4, be)


class TEAWithRounds(TEABase):
    rounds: int

    def __init__(self, key, mode, rounds: int = 32, big_endian: bool = False):
        super().__init__(key, mode, big_endian)
        self.rounds = rounds


class TEA(TEAWithRounds):
    """
    The TEA cipher.
    """
    def tea_encrypt(self, key: Sequence[int], block: Sequence[int]):
        k0, k1, k2, k3 = key
        v0, v1 = block
        carry = 0
        delta = 0x9E3779B9
        for _ in range(self.rounds):
            carry = (carry + delta) & 0xFFFFFFFF
            v0 = v0 + (((v1 << 4) + k0) ^ (v1 + carry) ^ (v1 >> 5) + k1) & 0xFFFFFFFF
            v1 = v1 + (((v0 << 4) + k2) ^ (v0 + carry) ^ (v0 >> 5) + k3) & 0xFFFFFFFF
        return (v0, v1)

    def tea_decrypt(self, key: Sequence[int], block: Sequence[int]):
        rounds = self.rounds
        k0, k1, k2, k3 = key
        v0, v1 = block
        delta = 0x9E3779B9
        carry = (delta * rounds) & 0xFFFFFFFF
        for _ in range(rounds):
            v1 = v1 - (((v0 << 4) + k2) ^ (v0 + carry) ^ (v0 >> 5) + k3) & 0xFFFFFFFF
            v0 = v0 - (((v1 << 4) + k0) ^ (v1 + carry) ^ (v1 >> 5) + k1) & 0xFFFFFFFF
            carry = (carry - delta) & 0xFFFFFFFF
        return (v0, v1)


class TEAUnit(StandardBlockCipherUnit):
    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False,
        swap: Param[bool, Arg.Switch('-s', help='Decode blocks as big endian rather than little endian.')] = False,
        rounds: Param[int, Arg.Number('-k', help='Specify the number of rounds, {default} by default.')] = 32,
        **more
    ):
        super().__init__(key, iv=iv, padding=padding, mode=mode, raw=raw, swap=swap, rounds=rounds, **more)

    @property
    def block_size(self):
        return 8

    def _new_cipher(self, **optionals) -> CipherInterface:
        return super()._new_cipher(
            big_endian=self.args.swap, rounds=self.args.rounds, **optionals)


class tea(TEAUnit, cipher=BlockCipherFactory(TEA)):
    """
    TEA encryption and decryption.
    """
