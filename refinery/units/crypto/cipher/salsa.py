from __future__ import annotations

import struct

from abc import ABC, abstractmethod
from typing import Iterable, Sequence, TypeVar

from Cryptodome.Cipher import Salsa20

from refinery.lib.crypto import PyCryptoFactoryWrapper, rotl32
from refinery.lib.types import asbuffer, buf
from refinery.units.crypto.cipher import LatinCipherStandardUnit, LatinCipherUnit


class LatinCipher(ABC):
    _idx_magic: slice
    _idx_key16: slice
    _idx_key32: slice
    _idx_nonce: slice
    _idx_count: slice
    _round_access_pattern: tuple[
        tuple[int, int, int, int],
        tuple[int, int, int, int],
        tuple[int, int, int, int],
        tuple[int, int, int, int],
        tuple[int, int, int, int],
        tuple[int, int, int, int],
        tuple[int, int, int, int],
        tuple[int, int, int, int],
    ]

    @staticmethod
    def _slice_words(s: slice) -> int:
        return len(range(*s.indices(16)))

    @classmethod
    def FromState(cls, state: Sequence[int] | buf):
        if b := asbuffer(state):
            state = struct.unpack('<16L', b)
        else:
            state = list(state)
        if len(state) != 16:
            raise ValueError('State must contain 16 DWORDs')
        nonce_words = cls._slice_words(cls._idx_nonce)
        count_words = cls._slice_words(cls._idx_count)
        key = struct.pack(
            '<8L', *state[cls._idx_key16], *state[cls._idx_key32])
        nonce = struct.pack(
            F'<{nonce_words}L', *state[cls._idx_nonce])
        magic = struct.pack(
            '<4L', *state[cls._idx_magic])
        count = int.from_bytes(struct.pack(
            F'<{count_words}L', *state[cls._idx_count]), 'little')
        return cls(key, nonce, magic, counter=count)

    def __init__(self, key: buf, nonce: buf, magic: buf | None = None, rounds: int = 20, counter: int = 0):
        nonce_words = self._slice_words(self._idx_nonce)
        nonce_size = 4 * nonce_words
        if len(key) == 16:
            key = 2 * bytes(key)
        elif len(key) != 32:
            raise ValueError('The key must be of length 16 or 32.')
        if rounds % 2:
            raise ValueError('The number of rounds has to be even.')
        if not nonce:
            nonce = bytearray(nonce_size)
        elif len(nonce) != nonce_size:
            raise ValueError(F'The nonce must be of length {nonce_size}.')
        if not magic:
            magic = B'expand %d-byte k' % len(key)
        elif len(magic) != 16:
            raise ValueError('The initialization magic must be 16 bytes in length.')
        _key = struct.unpack('<8L', key)
        self.key16 = _key[:4]
        self.key32 = _key[4:]
        self.magic = struct.unpack('<4L', magic)
        self.nonce = struct.unpack(F'<{nonce_words}L', nonce)
        self.state: list[int] = [0] * 4 * 4
        self.rounds = rounds // 2
        self.reset(counter)

    def reset(self, index=0) -> None:
        state = self.state
        count_words = self._slice_words(self._idx_count)
        self.counter = [index >> (32 * k) & 0xFFFFFFFF for k in range(count_words)]
        state[self._idx_magic] = self.magic
        state[self._idx_key16] = self.key16
        state[self._idx_key32] = self.key32
        state[self._idx_nonce] = self.nonce
        state[self._idx_count] = self.counter
        assert len(state) == 4 * 4

    def count(self):
        counter = self.counter
        for k, value in enumerate(counter):
            value = value + 1 & 0xFFFFFFFF
            counter[k] = value
            if value:
                break
        self.state[self._idx_count] = counter

    @staticmethod
    @abstractmethod
    def quarter(x: list[int], a: int, b: int, c: int, d: int):
        raise NotImplementedError

    def permute(self, x: list[int]):
        for a, b, c, d in self.rounds * self._round_access_pattern:
            self.quarter(x, a, b, c, d)

    def __iter__(self):
        x = [0] * len(self.state)
        while True:
            x[:] = self.state
            self.permute(x)
            yield from struct.pack('<16L', *(
                (a + b) & 0xFFFFFFFF for a, b in zip(x, self.state)))
            self.count()


class SalsaCipher(LatinCipher):
    _idx_magic = slice(0x00, 0x10, 0x05)
    _idx_key16 = slice(0x01, 0x05)
    _idx_key32 = slice(0x0B, 0x0F)
    _idx_nonce = slice(0x06, 0x08)
    _idx_count = slice(0x08, 0x0A)
    _round_access_pattern = (
        (0x0, 0x4, 0x8, 0xC),
        (0x5, 0x9, 0xD, 0x1),
        (0xA, 0xE, 0x2, 0x6),
        (0xF, 0x3, 0x7, 0xB),
        (0x0, 0x1, 0x2, 0x3),
        (0x5, 0x6, 0x7, 0x4),
        (0xA, 0xB, 0x8, 0x9),
        (0xF, 0xC, 0xD, 0xE),
    )

    @staticmethod
    def quarter(x: list[int], a: int, b: int, c: int, d: int) -> None:
        x[b] ^= rotl32(x[a] + x[d] & 0xFFFFFFFF, 0x07)
        x[c] ^= rotl32(x[b] + x[a] & 0xFFFFFFFF, 0x09)
        x[d] ^= rotl32(x[c] + x[b] & 0xFFFFFFFF, 0x0D)
        x[a] ^= rotl32(x[d] + x[c] & 0xFFFFFFFF, 0x12)


_X = TypeVar('_X', bound=LatinCipher)


def LatinX(
    cipher: type[_X],
    blocks: Iterable[int],
    key: buf,
    kdn: buf,
    kdp: int,
    nonce: buf,
    magic: buf,
    rounds: int,
    offset: int,
) -> _X:
    from refinery.lib import chunks
    kd = cipher(key, kdn, magic, rounds, kdp)
    kd.permute(kd.state)
    key = chunks.pack((kd.state[i] for i in blocks), 4)
    return cipher(key, nonce, magic, rounds, offset)


class salsa(LatinCipherUnit):
    """
    Salsa encryption and decryption.

    The nonce must be 8 bytes long. When 64 bytes are provided as the key, this data is interpreted
    as the initial state box and all other parameters are ignored.
    """
    def keystream(self) -> Iterable[int]:
        key = self.args.key
        if len(key) == 64:
            it = SalsaCipher.FromState(key)
        else:
            it = SalsaCipher(
                key,
                self.args.nonce,
                self.args.magic,
                self.args.rounds,
                self.args.offset,
            )
        yield from it


class xsalsa(LatinCipherUnit):
    """
    XSalsa encryption and decryption. The nonce must be 24 bytes long.
    """
    def keystream(self) -> Iterable[int]:
        kdn, kdp, nonce = struct.unpack('<8sQ8s', self.args.nonce)
        yield from LatinX(
            SalsaCipher,
            (0, 5, 10, 15, 6, 7, 8, 9),
            self.args.key,
            kdn,
            kdp,
            nonce,
            self.args.magic,
            self.args.rounds,
            self.args.offset,
        )


class salsa20(LatinCipherStandardUnit, cipher=PyCryptoFactoryWrapper(Salsa20)):
    """
    Salsa20 encryption and decryption.

    This unit is functionally equivalent to `refinery.salsa` with 20 rounds, but it uses the
    PyCryptodome library C implementation rather than the pure Python implementation used by
    `refinery.salsa`.
    """
