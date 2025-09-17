"""
This implementation of the SPECK cipher is based on the
[SPECK Implementation Guide](https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf) by the authors of SPECK.
"""
from __future__ import annotations

import struct

from refinery.lib.crypto import rotl32 as ROL32
from refinery.lib.crypto import rotl64 as ROL64
from refinery.lib.crypto import rotr32 as ROR32
from refinery.lib.crypto import rotr64 as ROR64

SPECK_ROUNDS = {
    "64_96": 26,
    "64_128": 27,
    "128_128": 32,
    "128_192": 33,
    "128_256": 34,
}


def make_dword(x: int) -> int:
    return x & 0xFFFFFFFF


def make_qword(x: int) -> int:
    return x & 0xFFFFFFFFFFFFFFFF


def words_to_bytes(words: list[int], word_size=32) -> bytes:
    numwords = len(words)
    if word_size == 32:
        bytes_out = struct.pack("<" + "I" * numwords, *words[::-1])
    elif word_size == 64:
        bytes_out = struct.pack("<" + "Q" * numwords, *words[::-1])
    return bytes_out


def bytes_to_words(bytes_in: bytes, word_size=32) -> list[int]:
    numbytes = len(bytes_in)
    if word_size == 32:
        numwords = numbytes // 4
        words = struct.unpack("<" + "I" * numwords, bytes_in)
    elif word_size == 64:
        numwords = numbytes // 8
        words = struct.unpack("<" + "Q" * numwords, bytes_in)
    return list(words[::-1])


def Speck6496KeySchedule(key: bytearray) -> list[int]:
    """
    Calculate the round key rk for SPECK 64/96
    """
    k = bytes_to_words(key)
    rk = []
    C = k[0]
    B = k[1]
    A = k[2]
    for i in range(0, SPECK_ROUNDS["64_96"], 2):
        rk.append(A)
        B, A = speck_encrypt_round32(B, A, i)
        rk.append(A)
        C, A = speck_encrypt_round32(C, A, i + 1)
    return rk


def Speck64128KeySchedule(key: bytearray) -> list[int]:
    """
    Calculate the round key rk for SPECK 64/128
    """
    k = bytes_to_words(key)
    rk = []
    D = k[0]
    C = k[1]
    B = k[2]
    A = k[3]
    for i in range(0, SPECK_ROUNDS["64_128"], 3):
        rk.append(A)
        B, A = speck_encrypt_round32(B, A, i)
        rk.append(A)
        C, A = speck_encrypt_round32(C, A, i + 1)
        rk.append(A)
        D, A = speck_encrypt_round32(D, A, i + 2)
    return rk


def Speck128128KeySchedule(key: bytearray) -> list[int]:
    """
    Calculate the round key rk for SPECK 128/128
    """
    k = bytes_to_words(key, 64)
    rk = []
    B = k[0]
    A = k[1]
    for i in range(0, SPECK_ROUNDS["128_128"]):
        rk.append(A)
        B, A = speck_encrypt_round64(B, A, i)
    rk.append(A)
    return rk


def Speck128192KeySchedule(key: bytearray) -> list[int]:
    """
    Calculate the round key rk for SPECK 128/192
    """
    k = bytes_to_words(key, 64)
    rk = []
    C = k[0]
    B = k[1]
    A = k[2]
    for i in range(0, SPECK_ROUNDS["128_192"] - 1, 2):
        rk.append(A)
        B, A = speck_encrypt_round64(B, A, i)
        rk.append(A)
        C, A = speck_encrypt_round64(C, A, i + 1)
    rk.append(A)
    return rk


def Speck128256KeySchedule(key: bytearray) -> list[int]:
    """
    Calculate the round key rk for SPECK 128/256
    """
    k = bytes_to_words(key, 64)
    rk = []
    D = k[0]
    C = k[1]
    B = k[2]
    A = k[3]
    for i in range(0, SPECK_ROUNDS["128_256"] - 1, 3):
        rk.append(A)
        B, A = speck_encrypt_round64(B, A, i)
        rk.append(A)
        C, A = speck_encrypt_round64(C, A, i + 1)
        rk.append(A)
        D, A = speck_encrypt_round64(D, A, i + 2)
    rk.append(A)
    return rk


def speck_encrypt_round32(x: int, y: int, k: int) -> tuple[int]:
    x = make_dword(ROR32(x, 8) + y) ^ k
    y = ROL32(y, 3) ^ x
    return x, y


def speck_encrypt_round64(x: int, y: int, k: int) -> tuple[int]:
    x = make_qword(ROR64(x, 8) + y) ^ k
    y = ROL64(y, 3) ^ x
    return x, y


def speck_decrypt_round32(x: int, y: int, k: int) -> tuple[int]:
    y = ROR32(y ^ x, 3)
    x = ROL32(make_dword((x ^ k) - y), 8)
    return x, y


def speck_decrypt_round64(x: int, y: int, k: int) -> tuple[int]:
    y = ROR64(y ^ x, 3)
    x = ROL64(make_qword((x ^ k) - y), 8)
    return x, y


def _internal_speck_encrypt32(plaintext: list[int], rk: list[int], rounds: int) -> list[int]:
    cipher = plaintext
    for i in range(0, rounds):
        cipher[0], cipher[1] = speck_encrypt_round32(cipher[0], cipher[1], rk[i])
    return cipher


def _internal_speck_encrypt64(plaintext: list[int], rk: list[int], rounds: int) -> list[int]:
    cipher = plaintext
    for i in range(0, rounds):
        cipher[0], cipher[1] = speck_encrypt_round64(cipher[0], cipher[1], rk[i])
    return cipher


def _internal_speck_decrypt32(cipher: list[int], rk: list[int], rounds: int) -> list[int]:
    plaintext = cipher
    for i in range(rounds - 1, -1, -1):
        plaintext[0], plaintext[1] = speck_decrypt_round32(plaintext[0], plaintext[1], rk[i])
    return plaintext


def _internal_speck_decrypt64(cipher: list[int], rk: list[int], rounds: int) -> list[int]:
    plaintext = cipher
    for i in range(rounds - 1, -1, -1):
        plaintext[0], plaintext[1] = speck_decrypt_round64(plaintext[0], plaintext[1], rk[i])
    return plaintext


def speck_encrypt32(plaintext: bytearray, rk: list[int], rounds: int) -> bytes:
    pt_words = bytes_to_words(plaintext)
    cipher = _internal_speck_encrypt32(pt_words, rk, rounds)
    return words_to_bytes(cipher)


def speck_encrypt64(plaintext: bytearray, rk: list[int], rounds: int) -> bytes:
    pt_words = bytes_to_words(plaintext, 64)
    cipher = _internal_speck_encrypt64(pt_words, rk, rounds)
    return words_to_bytes(cipher, 64)


def speck_decrypt32(cipher: bytearray, rk: list[int], rounds: int) -> bytes:
    ct_words = bytes_to_words(cipher)
    plaintext = _internal_speck_decrypt32(ct_words, rk, rounds)
    return words_to_bytes(plaintext)


def speck_decrypt64(cipher: bytearray, rk: list[int], rounds: int) -> bytes:
    ct_words = bytes_to_words(cipher, 64)
    plaintext = _internal_speck_decrypt64(ct_words, rk, rounds)
    return words_to_bytes(plaintext, 64)
