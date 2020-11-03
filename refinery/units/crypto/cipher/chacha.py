#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import ChaCha20
from typing import List, Iterable

from .salsa import LatinCipher
from . import LatinCipherUnit, LatinCipherStandardUnit
from ....lib.crypto import rotl32


class ChaChaCipher(LatinCipher):
    _idx_magic = slice(0x00, 0x04)
    _idx_key16 = slice(0x04, 0x08)
    _idx_key32 = slice(0x08, 0x0C)
    _idx_index = slice(0x0C, 0x0E)
    _idx_nonce = slice(0x0E, 0x10)
    _round_access_pattern = (
        (0x0, 0x4, 0x8, 0xC),
        (0x1, 0x5, 0x9, 0xD),
        (0x2, 0x6, 0xA, 0xE),
        (0x3, 0x7, 0xB, 0xF),
        (0x0, 0x5, 0xA, 0xF),
        (0x1, 0x6, 0xB, 0xC),
        (0x2, 0x7, 0x8, 0xD),
        (0x3, 0x4, 0x9, 0xE),
    )

    @staticmethod
    def quarter(x: List[int], a: int, b: int, c: int, d: int) -> None:
        x[a] = x[a] + x[b] & 0xFFFFFFFF; x[d] = rotl32(x[d] ^ x[a] & 0xFFFFFFFF, 0x10) # noqa
        x[c] = x[c] + x[d] & 0xFFFFFFFF; x[b] = rotl32(x[b] ^ x[c] & 0xFFFFFFFF, 0x0C) # noqa
        x[a] = x[a] + x[b] & 0xFFFFFFFF; x[d] = rotl32(x[d] ^ x[a] & 0xFFFFFFFF, 0x08) # noqa
        x[c] = x[c] + x[d] & 0xFFFFFFFF; x[b] = rotl32(x[b] ^ x[c] & 0xFFFFFFFF, 0x07) # noqa


class chacha20(LatinCipherStandardUnit, cipher=ChaCha20):
    """
    ChaCha20 and XChaCha20 encryption and decryption. For ChaCha20, the IV (nonce) must
    be 8 or 12 bytes long; for XChaCha20, choose an IV which is 24 bytes long. Invoking
    this unit for ChaCha20 is functionally equivalent to `refinery.chacha` with 20 rounds,
    but this unit uses the PyCryptodome library C implementation rather than the pure
    Python implementation used by `refinery.chacha`.
    """
    pass


class chacha(LatinCipherUnit):
    """
    ChaCha encryption and decryption. The nonce must be 8 bytes long as currently, only
    the original Bernstein algorithm is implemented.
    """
    def keystream(self) -> Iterable[int]:
        yield from ChaChaCipher(
            self.args.key,
            self.args.nonce,
            self.args.magic,
            self.args.rounds,
            self.args.offset
        )
