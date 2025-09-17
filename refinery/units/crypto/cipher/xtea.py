from __future__ import annotations

from typing import Sequence

from refinery.units.crypto.cipher.tea import BlockCipherFactory, TEAUnit, TEAWithRounds


class XTEA(TEAWithRounds):
    """
    The XTEA cipher.
    """
    def tea_encrypt(self, key: Sequence[int], block: Sequence[int]) -> tuple[int, int]:
        carry = 0
        delta = 0x9E3779B9
        v0, v1 = block
        for _ in range(self.rounds):
            v0 = v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (carry + key[carry & 3])) & 0xFFFFFFFF
            carry = carry + delta & 0xFFFFFFFF
            shift = carry >> 11
            v1 = v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (carry + key[shift & 3])) & 0xFFFFFFFF
        return (v0, v1)

    def tea_decrypt(self, key: Sequence[int], block: Sequence[int]) -> tuple[int, int]:
        rounds = self.rounds
        delta = 0x9E3779B9
        carry = (delta * rounds) & 0xFFFFFFFF
        v0, v1 = block
        for _ in range(rounds):
            shift = carry >> 11
            v1 = v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (carry + key[shift & 3])) & 0xFFFFFFFF
            carry = carry - delta & 0xFFFFFFFF
            v0 = v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (carry + key[carry & 3])) & 0xFFFFFFFF
        return (v0, v1)


class xtea(TEAUnit, cipher=BlockCipherFactory(XTEA)):
    """
    XTEA encryption and decryption.
    """
