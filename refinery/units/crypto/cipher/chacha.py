from __future__ import annotations

import struct

from typing import Iterable

from Cryptodome.Cipher import ChaCha20, ChaCha20_Poly1305

from refinery.lib.crypto import PyCryptoFactoryWrapper, rotl32
from refinery.units.crypto.cipher import LatinCipherStandardUnit, LatinCipherUnit
from refinery.units.crypto.cipher.salsa import LatinCipher, LatinX


class ChaChaCipher(LatinCipher):
    _idx_magic = slice(0x00, 0x04)
    _idx_key16 = slice(0x04, 0x08)
    _idx_key32 = slice(0x08, 0x0C)
    _idx_count = slice(0x0C, 0x0E)
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
    def quarter(x: list[int], a: int, b: int, c: int, d: int) -> None:
        x[a] = x[a] + x[b] & 0xFFFFFFFF; x[d] = rotl32(x[d] ^ x[a] & 0xFFFFFFFF, 0x10) # noqa
        x[c] = x[c] + x[d] & 0xFFFFFFFF; x[b] = rotl32(x[b] ^ x[c] & 0xFFFFFFFF, 0x0C) # noqa
        x[a] = x[a] + x[b] & 0xFFFFFFFF; x[d] = rotl32(x[d] ^ x[a] & 0xFFFFFFFF, 0x08) # noqa
        x[c] = x[c] + x[d] & 0xFFFFFFFF; x[b] = rotl32(x[b] ^ x[c] & 0xFFFFFFFF, 0x07) # noqa


class chacha20(LatinCipherStandardUnit, cipher=PyCryptoFactoryWrapper(ChaCha20)):
    """
    ChaCha20 and XChaCha20 encryption and decryption. For ChaCha20, the IV (nonce) must
    be 8 or 12 bytes long; for XChaCha20, choose an IV which is 24 bytes long. Invoking
    this unit for ChaCha20 is functionally equivalent to `refinery.chacha` with 20 rounds,
    but this unit uses the PyCryptodome library C implementation rather than the pure
    Python implementation used by `refinery.chacha`.
    """


class chacha20poly1305(LatinCipherStandardUnit, cipher=PyCryptoFactoryWrapper(ChaCha20_Poly1305)):
    """
    ChaCha20-Poly1305 and XChaCha20-Poly1305 encryption and decryption. For the ChaCha20
    variant, the nonce must be 8 or 12 bytes long; for XChaCha20, provide a 24 bytes nonce
    instead.
    """
    def _get_cipher(self, reset_cache=False):
        cipher = super()._get_cipher(reset_cache)
        cipher.block_size = 1
        return cipher


class chacha(LatinCipherUnit):
    """
    ChaCha encryption and decryption. The nonce must be 8 bytes long as currently, only the
    original Bernstein algorithm is implemented. When 64 bytes are provided as the key, this
    data is interpreted as the initial state box and all other parameters are ignored.
    """
    def keystream(self) -> Iterable[int]:
        key = self.args.key
        if len(key) == 64:
            it = ChaChaCipher.FromState(key)
        else:
            it = ChaChaCipher(
                key,
                self.args.nonce,
                self.args.magic,
                self.args.rounds,
                self.args.offset,
            )
        yield from it


class xchacha(LatinCipherUnit):
    """
    XChaCha encryption and decryption. The nonce must be 24 bytes long.
    """
    def keystream(self) -> Iterable[int]:
        kdp, kdn, nonce = struct.unpack('<Q8s8s', self.args.nonce)
        yield from LatinX(
            ChaChaCipher,
            (0, 1, 2, 3, 12, 13, 14, 15),
            self.args.key,
            kdn,
            kdp,
            nonce,
            self.args.magic,
            self.args.rounds,
            self.args.offset,
        )
