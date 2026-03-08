"""
This implementation of the SIMON cipher is based on the SIMON and SPECK
Implementation Guide by the authors of SIMON:
https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
"""
from __future__ import annotations

import struct

from refinery.lib.crypto import (
    rotl16,
    rotl24,
    rotl32,
    rotl48,
    rotl64,
    rotr16,
    rotr24,
    rotr32,
    rotr48,
    rotr64,
)

_z_seqs = (
    (1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0,
     1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0),
    (1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0,
     1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0),
    (1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0,
     0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1),
    (1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0,
     0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1),
    (1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0,
     0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1),
)


def words_to_bytes(words: list[int], word_size=32) -> bytes:
    numwords = len(words)
    if word_size == 16:
        return struct.pack(F'<{numwords}H', *words[::-1])
    elif word_size == 24:
        return b''.join(w.to_bytes(3, 'little') for w in reversed(words))
    elif word_size == 32:
        return struct.pack(F'<{numwords}I', *words[::-1])
    elif word_size == 48:
        return b''.join(w.to_bytes(6, 'little') for w in reversed(words))
    else:
        return struct.pack(F'<{numwords}Q', *words[::-1])


def bytes_to_words(bytes_in: bytes, word_size=32) -> list[int]:
    if word_size == 16:
        numwords = len(bytes_in) // 2
        words = struct.unpack(F'<{numwords}H', bytes_in)
    elif word_size == 24:
        numwords = len(bytes_in) // 3
        words = tuple(int.from_bytes(bytes_in[i * 3:(i + 1) * 3], 'little') for i in range(numwords))
    elif word_size == 32:
        numwords = len(bytes_in) // 4
        words = struct.unpack(F'<{numwords}I', bytes_in)
    elif word_size == 48:
        numwords = len(bytes_in) // 6
        words = tuple(int.from_bytes(bytes_in[i * 6:(i + 1) * 6], 'little') for i in range(numwords))
    else:
        numwords = len(bytes_in) // 8
        words = struct.unpack(F'<{numwords}Q', bytes_in)
    return list(words[::-1])


def simon_key_schedule_064_096(key: bytes, rounds: int = 42) -> list[int]:
    k = bytes_to_words(key)
    z = _z_seqs[2]
    rk = list(reversed(k))
    m = 3
    for i in range(m, rounds):
        tmp = rotr32(rk[i - 1], 3)
        tmp ^= rotr32(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFFFF)
    return rk


def simon_key_schedule_064_128(key: bytes, rounds: int = 44) -> list[int]:
    k = bytes_to_words(key)
    z = _z_seqs[3]
    rk = list(reversed(k))
    m = 4
    for i in range(m, rounds):
        tmp = rotr32(rk[i - 1], 3)
        tmp ^= rk[i - 3]
        tmp ^= rotr32(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFFFF)
    return rk


def simon_key_schedule_032_064(key: bytes, rounds: int = 32) -> list[int]:
    k = bytes_to_words(key, 16)
    z = _z_seqs[0]
    rk = list(reversed(k))
    m = 4
    for i in range(m, rounds):
        tmp = rotr16(rk[i - 1], 3)
        tmp ^= rk[i - 3]
        tmp ^= rotr16(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFF)
    return rk


def simon_key_schedule_048_072(key: bytes, rounds: int = 36) -> list[int]:
    k = bytes_to_words(key, 24)
    z = _z_seqs[0]
    rk = list(reversed(k))
    m = 3
    for i in range(m, rounds):
        tmp = rotr24(rk[i - 1], 3)
        tmp ^= rotr24(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFF)
    return rk


def simon_key_schedule_048_096(key: bytes, rounds: int = 36) -> list[int]:
    k = bytes_to_words(key, 24)
    z = _z_seqs[1]
    rk = list(reversed(k))
    m = 4
    for i in range(m, rounds):
        tmp = rotr24(rk[i - 1], 3)
        tmp ^= rk[i - 3]
        tmp ^= rotr24(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFF)
    return rk


def simon_key_schedule_096_096(key: bytes, rounds: int = 52) -> list[int]:
    k = bytes_to_words(key, 48)
    z = _z_seqs[2]
    rk = list(reversed(k))
    m = 2
    for i in range(m, rounds):
        tmp = rotr48(rk[i - 1], 3)
        tmp ^= rotr48(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFFFFFFFF)
    return rk


def simon_key_schedule_096_144(key: bytes, rounds: int = 54) -> list[int]:
    k = bytes_to_words(key, 48)
    z = _z_seqs[3]
    rk = list(reversed(k))
    m = 3
    for i in range(m, rounds):
        tmp = rotr48(rk[i - 1], 3)
        tmp ^= rotr48(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFFFFFFFF)
    return rk


def simon_key_schedule_128_128(key: bytes, rounds: int = 68) -> list[int]:
    k = bytes_to_words(key, 64)
    z = _z_seqs[2]
    rk = list(reversed(k))
    m = 2
    for i in range(m, rounds):
        tmp = rotr64(rk[i - 1], 3)
        tmp ^= rotr64(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFFFFFFFFFFFF)
    return rk


def simon_key_schedule_128_192(key: bytes, rounds: int = 69) -> list[int]:
    k = bytes_to_words(key, 64)
    z = _z_seqs[3]
    rk = list(reversed(k))
    m = 3
    for i in range(m, rounds):
        tmp = rotr64(rk[i - 1], 3)
        tmp ^= rotr64(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFFFFFFFFFFFF)
    return rk


def simon_key_schedule_128_256(key: bytes, rounds: int = 72) -> list[int]:
    k = bytes_to_words(key, 64)
    z = _z_seqs[4]
    rk = list(reversed(k))
    m = 4
    for i in range(m, rounds):
        tmp = rotr64(rk[i - 1], 3)
        tmp ^= rk[i - 3]
        tmp ^= rotr64(tmp, 1)
        rk.append((~rk[i - m] ^ tmp ^ z[(i - m) % 62] ^ 3) & 0xFFFFFFFFFFFFFFFF)
    return rk


def _simon_round16(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl16(x, 1) & rotl16(x, 8) & 0xFFFF) ^ y ^ rotl16(x, 2)
    return ((tmp ^ k) & 0xFFFF), x


def _simon_round24(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl24(x, 1) & rotl24(x, 8) & 0xFFFFFF) ^ y ^ rotl24(x, 2)
    return ((tmp ^ k) & 0xFFFFFF), x


def _simon_round32(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl32(x, 1) & rotl32(x, 8) & 0xFFFFFFFF) ^ y ^ rotl32(x, 2)
    return ((tmp ^ k) & 0xFFFFFFFF), x


def _simon_round48(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl48(x, 1) & rotl48(x, 8) & 0xFFFFFFFFFFFF) ^ y ^ rotl48(x, 2)
    return ((tmp ^ k) & 0xFFFFFFFFFFFF), x


def _simon_round64(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl64(x, 1) & rotl64(x, 8) & 0xFFFFFFFFFFFFFFFF) ^ y ^ rotl64(x, 2)
    return ((tmp ^ k) & 0xFFFFFFFFFFFFFFFF), x


def _simon_inv_round16(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl16(y, 1) & rotl16(y, 8) & 0xFFFF) ^ x ^ rotl16(y, 2)
    return y, ((tmp ^ k) & 0xFFFF)


def _simon_inv_round24(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl24(y, 1) & rotl24(y, 8) & 0xFFFFFF) ^ x ^ rotl24(y, 2)
    return y, ((tmp ^ k) & 0xFFFFFF)


def _simon_inv_round32(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl32(y, 1) & rotl32(y, 8) & 0xFFFFFFFF) ^ x ^ rotl32(y, 2)
    return y, ((tmp ^ k) & 0xFFFFFFFF)


def _simon_inv_round48(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl48(y, 1) & rotl48(y, 8) & 0xFFFFFFFFFFFF) ^ x ^ rotl48(y, 2)
    return y, ((tmp ^ k) & 0xFFFFFFFFFFFF)


def _simon_inv_round64(x: int, y: int, k: int) -> tuple[int, int]:
    tmp = (rotl64(y, 1) & rotl64(y, 8) & 0xFFFFFFFFFFFFFFFF) ^ x ^ rotl64(y, 2)
    return y, ((tmp ^ k) & 0xFFFFFFFFFFFFFFFF)


def simon_encrypt16(plaintext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(plaintext, 16)
    x, y = words[0], words[1]
    for i in range(rounds):
        x, y = _simon_round16(x, y, rk[i])
    return words_to_bytes([x, y], 16)


def simon_decrypt16(ciphertext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(ciphertext, 16)
    x, y = words[0], words[1]
    for i in range(rounds - 1, -1, -1):
        x, y = _simon_inv_round16(x, y, rk[i])
    return words_to_bytes([x, y], 16)


def simon_encrypt24(plaintext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(plaintext, 24)
    x, y = words[0], words[1]
    for i in range(rounds):
        x, y = _simon_round24(x, y, rk[i])
    return words_to_bytes([x, y], 24)


def simon_decrypt24(ciphertext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(ciphertext, 24)
    x, y = words[0], words[1]
    for i in range(rounds - 1, -1, -1):
        x, y = _simon_inv_round24(x, y, rk[i])
    return words_to_bytes([x, y], 24)


def simon_encrypt32(plaintext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(plaintext)
    x, y = words[0], words[1]
    for i in range(rounds):
        x, y = _simon_round32(x, y, rk[i])
    return words_to_bytes([x, y])


def simon_decrypt32(ciphertext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(ciphertext)
    x, y = words[0], words[1]
    for i in range(rounds - 1, -1, -1):
        x, y = _simon_inv_round32(x, y, rk[i])
    return words_to_bytes([x, y])


def simon_encrypt48(plaintext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(plaintext, 48)
    x, y = words[0], words[1]
    for i in range(rounds):
        x, y = _simon_round48(x, y, rk[i])
    return words_to_bytes([x, y], 48)


def simon_decrypt48(ciphertext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(ciphertext, 48)
    x, y = words[0], words[1]
    for i in range(rounds - 1, -1, -1):
        x, y = _simon_inv_round48(x, y, rk[i])
    return words_to_bytes([x, y], 48)


def simon_encrypt64(plaintext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(plaintext, 64)
    x, y = words[0], words[1]
    for i in range(rounds):
        x, y = _simon_round64(x, y, rk[i])
    return words_to_bytes([x, y], 64)


def simon_decrypt64(ciphertext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(ciphertext, 64)
    x, y = words[0], words[1]
    for i in range(rounds - 1, -1, -1):
        x, y = _simon_inv_round64(x, y, rk[i])
    return words_to_bytes([x, y], 64)
