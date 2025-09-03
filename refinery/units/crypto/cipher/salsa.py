from __future__ import annotations

import struct

from Cryptodome.Cipher import Salsa20
from abc import ABC, abstractmethod
from typing import List, Union, Sequence, Optional, Iterable, Tuple, Type, TypeVar

from refinery.units.crypto.cipher import LatinCipherUnit, LatinCipherStandardUnit
from refinery.lib.crypto import rotl32, PyCryptoFactoryWrapper
from refinery.lib.types import ByteStr


class LatinCipher(ABC):
    _idx_magic: slice
    _idx_key16: slice
    _idx_key32: slice
    _idx_nonce: slice
    _idx_count: slice
    _round_access_pattern: Tuple[Tuple[int, int, int, int], ...]

    @classmethod
    def FromState(cls, state: Union[Sequence[int], ByteStr]):
        try:
            state = struct.unpack('<16L', state)
        except TypeError:
            pass
        state: List[int] = list(state)
        if len(state) != 16:
            raise ValueError('State must contain 16 DWORDs')
        key = struct.pack(
            '<8L', *state[cls._idx_key16], *state[cls._idx_key32])
        nonce = struct.pack(
            '<2L', *state[cls._idx_nonce])
        magic = struct.pack(
            '<4L', *state[cls._idx_magic])
        count = int.from_bytes(struct.pack(
            '<2L', *state[cls._idx_count]), 'little')
        return cls(key, nonce, magic, counter=count)

    def __init__(self, key: ByteStr, nonce: ByteStr, magic: Optional[ByteStr] = None, rounds: int = 20, counter: int = 0):
        if len(key) == 16:
            key = 2 * key
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
        self.reset(counter)

    def reset(self, index=0) -> None:
        state = self.state
        self.counter = [index & 0xFFFFFFFF, index >> 32 & 0xFFFFFFFF]
        state[self._idx_magic] = self.magic
        state[self._idx_key16] = self.key16
        state[self._idx_key32] = self.key32
        state[self._idx_nonce] = self.nonce
        state[self._idx_count] = self.counter
        assert len(state) == 4 * 4

    def count(self):
        lo, hi = self.counter
        lo = lo + 1 & 0xFFFFFFFF
        if not lo:
            hi = hi + 1 & 0xFFFFFFFF
        self.state[self._idx_count] = self.counter = lo, hi

    @abstractmethod
    def quarter(self, x: List[int], a: int, b: int, c: int, d: int):
        raise NotImplementedError

    def permute(self, x: List[int]):
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
        (0xF, 0xC, 0xD, 0xE)
    )

    @staticmethod
    def quarter(x: List[int], a: int, b: int, c: int, d: int) -> None:
        x[b] ^= rotl32(x[a] + x[d] & 0xFFFFFFFF, 0x07)
        x[c] ^= rotl32(x[b] + x[a] & 0xFFFFFFFF, 0x09)
        x[d] ^= rotl32(x[c] + x[b] & 0xFFFFFFFF, 0x0D)
        x[a] ^= rotl32(x[d] + x[c] & 0xFFFFFFFF, 0x12)


_X = TypeVar('_X', bound=LatinCipher)


def LatinX(
    cipher: Type[_X],
    blocks: Iterable[int],
    key: ByteStr,
    kdn: ByteStr,
    kdp: ByteStr,
    nonce: ByteStr,
    magic: ByteStr,
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
    Salsa encryption and decryption. The nonce must be 8 bytes long. When 64 bytes are provided
    as the key, this data is interpreted as the initial state box and all other parameters are
    ignored.
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
    Salsa20 encryption and decryption. This unit is functionally equivalent to `refinery.salsa`
    with 20 rounds, but it uses the PyCryptodome library C implementation rather than the pure
    Python implementation used by `refinery.salsa`.
    """
    pass
