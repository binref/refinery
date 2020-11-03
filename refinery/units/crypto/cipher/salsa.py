#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct

from Crypto.Cipher import Salsa20
from abc import ABC, abstractmethod
from typing import List, ByteString, Optional, Iterable

from . import LatinCipherUnit, LatinCipherStandardUnit
from ....lib.crypto import rotl32


class LatinCipher(ABC):
    def __init__(self, key: ByteString, nonce: ByteString, magic: Optional[ByteString] = None, rounds: int = 20, index: int = 0):
        if len(key) == 16:
            key += key
        elif len(key) != 32:
            raise ValueError('The key must be of length 16 or 32.')
        if rounds % 2:
            raise ValueError('The number of rounds has to be even.')
        if not nonce:
            nonce = bytearray(8)
        elif len(nonce) != 8:
            raise ValueError('The nonce must be of length 8.')
        if magic:
            if len(magic) != 16:
                raise ValueError('The initialization magic must be 16 bytes in length.')
        elif len(key) == 16:
            magic = B'expand 16-byte k'
        elif len(key) == 32:
            magic = B'expand 32-byte k'
        key = struct.unpack('<8L', key)
        self.key16 = key[:4]
        self.key32 = key[4:]
        self.magic = struct.unpack('<4L', magic)
        self.nonce = struct.unpack('<2L', nonce)
        self.state: List[int] = [0] * 4 * 4
        self.rounds = rounds // 2
        self.reset(index)

    def reset(self, index=0) -> None:
        state = self.state
        self.index = [index & 0xFFFFFFFF, index >> 32 & 0xFFFFFFFF]
        state[self._idx_magic] = self.magic
        state[self._idx_key16] = self.key16
        state[self._idx_key32] = self.key32
        state[self._idx_nonce] = self.nonce
        state[self._idx_index] = self.index
        assert len(state) == 4 * 4

    def count(self):
        lo, hi = self.index
        lo = lo + 1 & 0xFFFFFFFF
        if not lo:
            hi = hi + 1 & 0xFFFFFFFF
        self.state[self._idx_index] = self.index = lo, hi

    @abstractmethod
    def quarter(self, x: List[int], a: int, b: int, c: int, d: int):
        raise NotImplementedError

    def __iter__(self):
        while True:
            x = list(self.state)
            for p in self.rounds * self._round_access_pattern:
                self.quarter(x, *p)
            yield from struct.pack('<16L', *(
                (a + b) & 0xFFFFFFFF for a, b in zip(x, self.state)))
            self.count()


class SalsaCipher(LatinCipher):
    _idx_magic = slice(0x00, 0x10, 0x05)
    _idx_key16 = slice(0x01, 0x05)
    _idx_key32 = slice(0x0B, 0x0F)
    _idx_nonce = slice(0x06, 0x08)
    _idx_index = slice(0x08, 0x0A)
    _round_access_pattern = (
        (0x0, 0x4, 0x8, 0xC),
        (0x5, 0x9, 0xD, 0x1),
        (0xA, 0xE, 0x2, 0x6),
        (0xF, 0x3, 0x7, 0xB),
        (0x0, 0x1, 0x2, 0x3),
        (0x5, 0x6, 0x7, 0x4),
        (0xA, 0xB, 0x8, 0x9),
        (0xF, 0xC, 0xD, 0xE)
    )

    @staticmethod
    def quarter(x: List[int], a: int, b: int, c: int, d: int) -> None:
        x[b] ^= rotl32(x[a] + x[d] & 0xFFFFFFFF, 0x07)
        x[c] ^= rotl32(x[b] + x[a] & 0xFFFFFFFF, 0x09)
        x[d] ^= rotl32(x[c] + x[b] & 0xFFFFFFFF, 0x0D)
        x[a] ^= rotl32(x[d] + x[c] & 0xFFFFFFFF, 0x12)


class salsa(LatinCipherUnit):
    """
    Salsa encryption and decryption. The nonce must be 8 bytes long.
    """
    def keystream(self) -> Iterable[int]:
        yield from SalsaCipher(
            self.args.key,
            self.args.nonce,
            self.args.magic,
            self.args.rounds,
            self.args.offset
        )


class salsa20(LatinCipherStandardUnit, cipher=Salsa20):
    """
    Salsa20 encryption and decryption. This unit is functionally equivalent to `refinery.salsa`
    with 20 rounds, but it uses the PyCryptodome library C implementation rather than the pure
    Python implementation used by `refinery.salsa`.
    """
    pass
