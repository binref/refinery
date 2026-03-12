"""
This implementation of the SPECK cipher is based on the
[SPECK Implementation Guide](https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf) by the authors of SPECK.
"""
from __future__ import annotations

import struct

from refinery.lib.crypto import (
    rotl32,
    rotl64,
    rotr32,
    rotr64,
)


def words_to_bytes(words: list[int], word_size=32) -> bytes:
    numwords = len(words)
    if word_size == 32:
        return struct.pack(F'<{numwords}I', *words[::-1])
    else:
        return struct.pack(F'<{numwords}Q', *words[::-1])


def bytes_to_words(bytes_in: bytes, word_size=32) -> list[int]:
    if word_size == 32:
        numwords = len(bytes_in) // 4
        words = struct.unpack(F'<{numwords}I', bytes_in)
    else:
        numwords = len(bytes_in) // 8
        words = struct.unpack(F'<{numwords}Q', bytes_in)
    return list(words[::-1])


def speck_key_schedule_064_096(key: bytes, rounds: int = 26) -> list[int]:
    k = bytes_to_words(key)
    rk = []
    C = k[0]
    B = k[1]
    A = k[2]
    for i in range(0, rounds, 2):
        rk.append(A)
        B, A = speck_encrypt_round32(B, A, i)
        rk.append(A)
        C, A = speck_encrypt_round32(C, A, i + 1)
    return rk


def speck_key_schedule_064_128(key: bytes, rounds: int = 27) -> list[int]:
    k = bytes_to_words(key)
    rk = []
    D = k[0]
    C = k[1]
    B = k[2]
    A = k[3]
    for i in range(0, rounds, 3):
        rk.append(A)
        B, A = speck_encrypt_round32(B, A, i)
        rk.append(A)
        C, A = speck_encrypt_round32(C, A, i + 1)
        rk.append(A)
        D, A = speck_encrypt_round32(D, A, i + 2)
    return rk


def speck_key_schedule_128_128(key: bytes, rounds: int = 32) -> list[int]:
    k = bytes_to_words(key, 64)
    rk = []
    B = k[0]
    A = k[1]
    for i in range(0, rounds):
        rk.append(A)
        B, A = speck_encrypt_round64(B, A, i)
    rk.append(A)
    return rk


def speck_key_schedule_128_192(key: bytes, rounds: int = 33) -> list[int]:
    k = bytes_to_words(key, 64)
    rk = []
    C = k[0]
    B = k[1]
    A = k[2]
    for i in range(0, rounds - 1, 2):
        rk.append(A)
        B, A = speck_encrypt_round64(B, A, i)
        rk.append(A)
        C, A = speck_encrypt_round64(C, A, i + 1)
    rk.append(A)
    return rk


def speck_key_schedule_128_256(key: bytes, rounds: int = 34) -> list[int]:
    k = bytes_to_words(key, 64)
    rk = []
    D = k[0]
    C = k[1]
    B = k[2]
    A = k[3]
    for i in range(0, rounds - 1, 3):
        rk.append(A)
        B, A = speck_encrypt_round64(B, A, i)
        rk.append(A)
        C, A = speck_encrypt_round64(C, A, i + 1)
        rk.append(A)
        D, A = speck_encrypt_round64(D, A, i + 2)
    rk.append(A)
    return rk


def speck_encrypt_round32(x: int, y: int, k: int) -> tuple[int, int]:
    x = ((rotr32(x, 8) + y) & 0xFFFFFFFF) ^ k
    y = rotl32(y, 3) ^ x
    return x, y


def speck_encrypt_round64(x: int, y: int, k: int) -> tuple[int, int]:
    x = ((rotr64(x, 8) + y) & 0xFFFFFFFFFFFFFFFF) ^ k
    y = rotl64(y, 3) ^ x
    return x, y


def speck_decrypt_round32(x: int, y: int, k: int) -> tuple[int, int]:
    y = rotr32(y ^ x, 3)
    x = rotl32(((x ^ k) - y) & 0xFFFFFFFF, 8)
    return x, y


def speck_decrypt_round64(x: int, y: int, k: int) -> tuple[int, int]:
    y = rotr64(y ^ x, 3)
    x = rotl64(((x ^ k) - y) & 0xFFFFFFFFFFFFFFFF, 8)
    return x, y


def speck_encrypt32(plaintext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(plaintext)
    x, y = words[0], words[1]
    for i in range(rounds):
        x, y = speck_encrypt_round32(x, y, rk[i])
    return words_to_bytes([x, y])


def speck_encrypt64(plaintext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(plaintext, 64)
    x, y = words[0], words[1]
    for i in range(rounds):
        x, y = speck_encrypt_round64(x, y, rk[i])
    return words_to_bytes([x, y], 64)


def speck_decrypt32(ciphertext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(ciphertext)
    x, y = words[0], words[1]
    for i in range(rounds - 1, -1, -1):
        x, y = speck_decrypt_round32(x, y, rk[i])
    return words_to_bytes([x, y])


def speck_decrypt64(ciphertext: bytes, rk: list[int], rounds: int | None = None) -> bytes:
    if rounds is None:
        rounds = len(rk)
    words = bytes_to_words(ciphertext, 64)
    x, y = words[0], words[1]
    for i in range(rounds - 1, -1, -1):
        x, y = speck_decrypt_round64(x, y, rk[i])
    return words_to_bytes([x, y], 64)
