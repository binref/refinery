from __future__ import annotations

from typing import Sequence

from refinery.lib.crypto import BlockCipherFactory, BufferType, CipherInterface, CipherMode
from refinery.lib.types import Param
from refinery.units.crypto.cipher.tea import Arg, StandardBlockCipherUnit, TEABase, TEAUnit


class XXTEA(TEABase):

    def __init__(
        self,
        key: BufferType,
        mode: CipherMode | None,
        big_endian: bool = False,
        block_size: int = TEABase.block_size
    ):
        self.block_size = block_size
        super().__init__(key, mode, big_endian)

    def tea_encrypt(self, key: Sequence[int], v: Sequence[int]) -> Sequence[int]:
        n = len(v)
        s = 0
        r = 6 + 52 // n
        z = v[n - 1]
        for _ in range(r):
            s = s + 0x9E3779B9 & 0xFFFFFFFF
            e = (s >> 2) & 3
            for p in range(n):
                y = v[(p + 1) % n]
                k = (p & 3) ^ e
                x = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (s ^ y) + (key[k] ^ z)
                z = v[p] = v[p] + x & 0xFFFFFFFF
        return v

    def tea_decrypt(self, key: Sequence[int], v: Sequence[int]) -> Sequence[int]:
        n = len(v)
        r = 6 + 52 // n
        s = r * 0x9E3779B9 & 0xFFFFFFFF
        y = v[0]
        for _ in range(r):
            e = (s >> 2) & 3
            for p in range(n - 1, -1, -1):
                z = v[(p - 1) % n]
                k = (p & 3) ^ e
                x = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (s ^ y) + (key[k] ^ z)
                y = v[p] = v[p] - x & 0xFFFFFFFF
            s = s - 0x9E3779B9 & 0xFFFFFFFF
        return v


class xxtea(TEAUnit, cipher=BlockCipherFactory(XXTEA)):

    block_size: int = 4

    def __init__(
        self, key, iv=b'', padding=None, mode=None, raw=False, swap=False,
        block_size: Param[int, Arg.Number('-b', help=(
            'Cipher block size in 32-bit words. The default value {default} implies that the input '
            'is treated as a single block, which is common behaviour of many implementations.'))] = 1
    ):
        super().__init__(
            key, iv=iv, padding=padding, mode=mode, raw=raw, swap=swap, block_size=block_size)

    def _prepare_block(self, data: bytes):
        if self.args.block_size <= 1:
            blocks, remainder = divmod(len(data), 4)
            if remainder:
                blocks += 1
            self.block_size = blocks * 4
        else:
            self.block_size = self.args.block_size * 4

    def encrypt(self, data: bytes) -> bytes:
        self._prepare_block(data)
        return super().encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        self._prepare_block(data)
        return super().decrypt(data)

    def _new_cipher(self, **optionals) -> CipherInterface:
        return StandardBlockCipherUnit._new_cipher(self,
            big_endian=self.args.swap, block_size=self.block_size, **optionals)
