from __future__ import annotations

from struct import pack, unpack
from typing import Tuple

from refinery.lib.crypto import (
    BlockCipher,
    BlockCipherFactory,
    BufferType,
    CipherInterface,
    CipherMode,
    rotl32,
    rotr32,
)
from refinery.lib.types import Param
from refinery.units.crypto.cipher import (
    Arg,
    StandardBlockCipherUnit,
)

_R = 12
_K = Tuple[int, int, int, int]


class Chaskey(BlockCipher):

    key_size = {0x10}
    block_size = 0x10

    _k: tuple[_K, _K, _K] | None
    _s: bool
    _r: int

    def __init__(self, key: BufferType, mode: CipherMode | None, swap: bool = False, rounds: int = _R):
        self._r = rounds
        self._f = '>IIII' if swap else '<IIII'
        self._k = None
        super().__init__(key, mode)

    def block_encrypt(self, block) -> BufferType:
        f = self._f
        r = self._r
        v0, v1, v2, v3 = unpack(f, block)
        k0, k1, k2, k3 = self._k
        v0 ^= k0
        v1 ^= k1
        v2 ^= k2
        v3 ^= k3
        for _ in range(r):
            v0 = v0 + v1 & 0xFFFFFFFF
            v1 = rotl32(v1, 0x05) ^ v0
            v0 = rotl32(v0, 0x10)
            v2 = v2 + v3 & 0xFFFFFFFF
            v3 = rotl32(v3, 0x08) ^ v2
            v0 = v0 + v3 & 0xFFFFFFFF
            v3 = rotl32(v3, 0x0D) ^ v0
            v2 = v2 + v1 & 0xFFFFFFFF
            v1 = rotl32(v1, 0x07) ^ v2
            v2 = rotl32(v2, 0x10)
        v0 ^= k0
        v1 ^= k1
        v2 ^= k2
        v3 ^= k3
        return pack(f, v0, v1, v2, v3)

    def block_decrypt(self, block) -> BufferType:
        f = self._f
        r = self._r
        k0, k1, k2, k3 = self._k
        v0, v1, v2, v3 = unpack(f, block)
        v0 ^= k0
        v1 ^= k1
        v2 ^= k2
        v3 ^= k3
        for _ in range(r):
            v2 = rotr32(v2, 0x10)
            v1 = rotr32(v1 ^ v2, 0x07)
            v2 = v2 - v1 & 0xFFFFFFFF
            v3 = rotr32(v3 ^ v0, 0x0D)
            v0 = v0 - v3 & 0xFFFFFFFF
            v3 = rotr32(v3 ^ v2, 0x08)
            v2 = v2 - v3 & 0xFFFFFFFF
            v0 = rotr32(v0, 0x10)
            v1 = rotr32(v1 ^ v0, 0x05)
            v0 = v0 - v1 & 0xFFFFFFFF
        v0 ^= k0
        v1 ^= k1
        v2 ^= k2
        v3 ^= k3
        return pack(f, v0, v1, v2, v3)

    @property
    def key(self):
        return self._k

    @key.setter
    def key(self, key: bytes):
        self._k = unpack(self._f, key)


class chaskey(StandardBlockCipherUnit, cipher=BlockCipherFactory(Chaskey)):
    """
    This implements a block cipher based on the Chaskey algorithm. No subkeys are computed and the
    default Chaskey operation is performed on all blocks. Notably, the Donut framework uses Chaskey
    with 16 rounds and in CTR mode.
    """
    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False,
        rounds: Param[int, Arg.Number('-k', help='Number of rounds to use, the default is {default}')] = _R,
        swap: Param[bool, Arg.Switch('-s', help='Use big endian byte order for all blocks.')] = False,
        **more
    ):
        super().__init__(key, iv=iv, padding=padding, mode=mode, raw=raw, rounds=rounds, swap=swap, **more)

    def _new_cipher(self, **optionals) -> CipherInterface:
        return super()._new_cipher(
            swap=self.args.swap,
            rounds=self.args.rounds,
            **optionals
        )
