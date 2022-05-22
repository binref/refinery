#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
"""
This implementation of the Serpent cipher is based on the original C reference implementation, available
from the [official website](https://www.cl.cam.ac.uk/~rja14/serpent.html). The C macros for each of the
round operations were turned into a Python function, and the unrolled loops were reverted back because the
performance gain in Python would be negligible for the substantial loss of readability.

All functions allow a "swap" option to be passed which will has the equivalent effect of reversing the
byte order of the input. This option is available because different implementations use different byte
orders for the various parts of the algorithm.
"""
from __future__ import annotations

from typing import List
from struct import pack, unpack

from refinery.lib.crypto import (
    rotl32 as ROL,
    rotr32 as ROR,
)

PHI = 0x9E3779B9


def RND00(a, b, c, d):
    t01 = b   ^ c
    t02 = a   | d
    t03 = a   ^ b
    z   = t02 ^ t01
    t05 = c   | z
    t06 = a   ^ d
    t07 = b   | c
    t08 = d   & t05
    t09 = t03 & t07
    y   = t09 ^ t08
    t11 = t09 & y
    t12 = c   ^ d
    t13 = t07 ^ t11
    t14 = b   & t06
    t15 = t06 ^ t13
    w   =     ~ t15 & 0xFFFFFFFF
    t17 = w   ^ t14
    x   = t12 ^ t17
    return w, x, y, z


def RND01(a, b, c, d):
    t01 = a   | d
    t02 = c   ^ d
    t03 =     ~ b & 0xFFFFFFFF
    t04 = a   ^ c
    t05 = a   | t03
    t06 = d   & t04
    t07 = t01 & t02
    t08 = b   | t06
    y   = t02 ^ t05
    t10 = t07 ^ t08
    t11 = t01 ^ t10
    t12 = y   ^ t11
    t13 = b   & d
    z   =     ~ t10 & 0xFFFFFFFF
    x   = t13 ^ t12
    t16 = t10 | x
    t17 = t05 & t16
    w   = c   ^ t17
    return w, x, y, z


def RND02(a, b, c, d):
    t01 = a   | c
    t02 = a   ^ b
    t03 = d   ^ t01
    w   = t02 ^ t03
    t05 = c   ^ w
    t06 = b   ^ t05
    t07 = b   | t05
    t08 = t01 & t06
    t09 = t03 ^ t07
    t10 = t02 | t09
    x   = t10 ^ t08
    t12 = a   | d
    t13 = t09 ^ x
    t14 = b   ^ t13
    z   =     ~ t09 & 0xFFFFFFFF
    y   = t12 ^ t14
    return w, x, y, z


def RND03(a, b, c, d):
    t01 = a   ^ c
    t02 = a   | d
    t03 = a   & d
    t04 = t01 & t02
    t05 = b   | t03
    t06 = a   & b
    t07 = d   ^ t04
    t08 = c   | t06
    t09 = b   ^ t07
    t10 = d   & t05
    t11 = t02 ^ t10
    z   = t08 ^ t09
    t13 = d   | z
    t14 = a   | t07
    t15 = b   & t13
    y   = t08 ^ t11
    w   = t14 ^ t15
    x   = t05 ^ t04
    return w, x, y, z


def RND04(a, b, c, d):
    t01 = a   | b
    t02 = b   | c
    t03 = a   ^ t02
    t04 = b   ^ d
    t05 = d   | t03
    t06 = d   & t01
    z   = t03 ^ t06
    t08 = z   & t04
    t09 = t04 & t05
    t10 = c   ^ t06
    t11 = b   & c
    t12 = t04 ^ t08
    t13 = t11 | t03
    t14 = t10 ^ t09
    t15 = a   & t05
    t16 = t11 | t12
    y   = t13 ^ t08
    x   = t15 ^ t16
    w   =     ~ t14 & 0xFFFFFFFF
    return w, x, y, z


def RND05(a, b, c, d):
    t01 = b   ^ d
    t02 = b   | d
    t03 = a   & t01
    t04 = c   ^ t02
    t05 = t03 ^ t04
    w   =     ~ t05 & 0xFFFFFFFF
    t07 = a   ^ t01
    t08 = d   | w
    t09 = b   | t05
    t10 = d   ^ t08
    t11 = b   | t07
    t12 = t03 | w
    t13 = t07 | t10
    t14 = t01 ^ t11
    y   = t09 ^ t13
    x   = t07 ^ t08
    z   = t12 ^ t14
    return w, x, y, z


def RND06(a, b, c, d):
    t01 = a   & d
    t02 = b   ^ c
    t03 = a   ^ d
    t04 = t01 ^ t02
    t05 = b   | c
    x   =     ~ t04 & 0xFFFFFFFF
    t07 = t03 & t05
    t08 = b   & x
    t09 = a   | c
    t10 = t07 ^ t08
    t11 = b   | d
    t12 = c   ^ t11
    t13 = t09 ^ t10
    y   =     ~ t13 & 0xFFFFFFFF
    t15 = x   & t03
    z   = t12 ^ t07
    t17 = a   ^ b
    t18 = y   ^ t15
    w   = t17 ^ t18
    return w, x, y, z


def RND07(a, b, c, d):
    t01 = a   & c
    t02 =     ~ d & 0xFFFFFFFF
    t03 = a   & t02
    t04 = b   | t01
    t05 = a   & b
    t06 = c   ^ t04
    z   = t03 ^ t06
    t08 = c   | z
    t09 = d   | t05
    t10 = a   ^ t08
    t11 = t04 & z
    x   = t09 ^ t10
    t13 = b   ^ x
    t14 = t01 ^ x
    t15 = c   ^ t05
    t16 = t11 | t13
    t17 = t02 | t14
    w   = t15 ^ t17
    y   = a   ^ t16
    return w, x, y, z


def make_subkeys(key: bytearray, swap: bool = False):
    if len(key) > 32:
        raise ValueError
    if swap:
        key = key[::-1]
    key = B'\0' * (-len(key) % 4) + key
    K = [0] * 132
    L = len(key) // 4
    for i, v in enumerate(reversed(unpack(F'>{L}L', key))):
        K[i] = v
    if L < 8:
        K[L] = 1
    for i in range(8, 16):
        K[i] = ROL(K[i-8] ^ K[i-5] ^ K[i-3] ^ K[i-1] ^ PHI ^ (i-8), 11)
    K[:8] = K[8:16]
    for i in range(8, 132):
        K[i] = ROL(K[i-8] ^ K[i-5] ^ K[i-3] ^ K[i-1] ^ PHI ^ i, 11)
    RNDS = [RND00, RND01, RND02, RND03, RND04, RND05, RND06, RND07]
    for i, k in enumerate(range(3, -30, -1)):
        a, b = i * 4, (i + 1) * 4
        K[a:b] = RNDS[k % 8](*K[a:b])
    return K


def serpent_encrypt(plaintext: bytearray, subkeys: List[int], swap: bool = False) -> bytes:
    if swap:
        a, b, c, d = unpack('<4L', plaintext)
    else:
        d, c, b, a = unpack('>4L', plaintext)

    RNDS = [RND00, RND01, RND02, RND03, RND04, RND05, RND06, RND07]

    for k in range(31):
        j = k * 4
        a ^= subkeys[j + 0]
        b ^= subkeys[j + 1]
        c ^= subkeys[j + 2]
        d ^= subkeys[j + 3]
        w, x, y, z = RNDS[k % 8](a, b, c, d)
        a = ROL(w, 13)
        c = ROL(y, 3)
        b = x ^ a ^ c
        d = z ^ c ^ ((a<<3) & 0xFFFFFFFF)
        b = ROL(b, 1)
        d = ROL(d, 7)
        a = a ^ b ^ d
        c = c ^ d ^ ((b<<7) & 0xFFFFFFFF)
        a = ROL(a, 5)
        c = ROL(c, 22)

    a ^= subkeys[124]
    b ^= subkeys[125]
    c ^= subkeys[126]
    d ^= subkeys[127]

    a, b, c, d = RND07(a, b, c, d)

    a ^= subkeys[128]
    b ^= subkeys[129]
    c ^= subkeys[130]
    d ^= subkeys[131]

    if swap:
        return pack('<4L', a, b, c, d)
    else:
        return pack('>4L', d, c, b, a)


def InvRND00(a, b, c, d):
    t01 = c   ^ d
    t02 = a   | b
    t03 = b   | c
    t04 = c   & t01
    t05 = t02 ^ t01
    t06 = a   | t04
    y   =     ~ t05 & 0xFFFFFFFF
    t08 = b   ^ d
    t09 = t03 & t08
    t10 = d   | y
    x   = t09 ^ t06
    t12 = a   | t05
    t13 = x   ^ t12
    t14 = t03 ^ t10
    t15 = a   ^ c
    z   = t14 ^ t13
    t17 = t05 & t13
    t18 = t14 | t17
    w   = t15 ^ t18
    return w, x, y, z


def InvRND01(a, b, c, d):
    t01 = a   ^ b
    t02 = b   | d
    t03 = a   & c
    t04 = c   ^ t02
    t05 = a   | t04
    t06 = t01 & t05
    t07 = d   | t03
    t08 = b   ^ t06
    t09 = t07 ^ t06
    t10 = t04 | t03
    t11 = d   & t08
    y   =     ~ t09 & 0xFFFFFFFF
    x   = t10 ^ t11
    t14 = a   | y
    t15 = t06 ^ x
    z   = t01 ^ t04
    t17 = c   ^ t15
    w   = t14 ^ t17
    return w, x, y, z


def InvRND02(a, b, c, d):
    t01 = a   ^ d
    t02 = c   ^ d
    t03 = a   & c
    t04 = b   | t02
    w   = t01 ^ t04
    t06 = a   | c
    t07 = d   | w
    t08 =     ~ d & 0xFFFFFFFF
    t09 = b   & t06
    t10 = t08 | t03
    t11 = b   & t07
    t12 = t06 & t02
    z   = t09 ^ t10
    x   = t12 ^ t11
    t15 = c   & z
    t16 = w   ^ x
    t17 = t10 ^ t15
    y   = t16 ^ t17
    return w, x, y, z


def InvRND03(a, b, c, d):
    t01 = c   | d
    t02 = a   | d
    t03 = c   ^ t02
    t04 = b   ^ t02
    t05 = a   ^ d
    t06 = t04 & t03
    t07 = b   & t01
    y   = t05 ^ t06
    t09 = a   ^ t03
    w   = t07 ^ t03
    t11 = w   | t05
    t12 = t09 & t11
    t13 = a   & y
    t14 = t01 ^ t05
    x   = b   ^ t12
    t16 = b   | t13
    z   = t14 ^ t16
    return w, x, y, z


def InvRND04(a, b, c, d):
    t01 = b   | d
    t02 = c   | d
    t03 = a   & t01
    t04 = b   ^ t02
    t05 = c   ^ d
    t06 =     ~ t03 & 0xFFFFFFFF
    t07 = a   & t04
    x   = t05 ^ t07
    t09 = x   | t06
    t10 = a   ^ t07
    t11 = t01 ^ t09
    t12 = d   ^ t04
    t13 = c   | t10
    z   = t03 ^ t12
    t15 = a   ^ t04
    y   = t11 ^ t13
    w   = t15 ^ t09
    return w, x, y, z


def InvRND05(a, b, c, d):
    t01 = a   & d
    t02 = c   ^ t01
    t03 = a   ^ d
    t04 = b   & t02
    t05 = a   & c
    w   = t03 ^ t04
    t07 = a   & w
    t08 = t01 ^ w
    t09 = b   | t05
    t10 =     ~ b & 0xFFFFFFFF
    x   = t08 ^ t09
    t12 = t10 | t07
    t13 = w   | x
    z   = t02 ^ t12
    t15 = t02 ^ t13
    t16 = b   ^ d
    y   = t16 ^ t15
    return w, x, y, z


def InvRND06(a, b, c, d):
    t01 = a   ^ c
    t02 =     ~ c & 0xFFFFFFFF
    t03 = b   & t01
    t04 = b   | t02
    t05 = d   | t03
    t06 = b   ^ d
    t07 = a   & t04
    t08 = a   | t02
    t09 = t07 ^ t05
    x   = t06 ^ t08
    w   =     ~ t09 & 0xFFFFFFFF
    t12 = b   & w
    t13 = t01 & t05
    t14 = t01 ^ t12
    t15 = t07 ^ t13
    t16 = d   | t02
    t17 = a   ^ x
    z   = t17 ^ t15
    y   = t16 ^ t14
    return w, x, y, z


def InvRND07(a, b, c, d):
    t01 = a   & b
    t02 = a   | b
    t03 = c   | t01
    t04 = d   & t02
    z   = t03 ^ t04
    t06 = b   ^ t04
    t07 = d   ^ z
    t08 =     ~ t07 & 0xFFFFFFFF
    t09 = t06 | t08
    t10 = b   ^ d
    t11 = a   | d
    x   = a   ^ t09
    t13 = c   ^ t06
    t14 = c   & t11
    t15 = d   | x
    t16 = t01 | t10
    w   = t13 ^ t15
    y   = t14 ^ t16
    return w, x, y, z


def serpent_decrypt(ciphertext: bytearray, subkeys: List[int], swap: bool = False) -> bytes:
    if swap:
        a, b, c, d = unpack('<4L', ciphertext)
    else:
        d, c, b, a = unpack('>4L', ciphertext)

    RNDS = [InvRND00, InvRND01, InvRND02, InvRND03, InvRND04, InvRND05, InvRND06, InvRND07]

    a ^= subkeys[128]
    b ^= subkeys[129]
    c ^= subkeys[130]
    d ^= subkeys[131]

    w, x, y, z = InvRND07(a, b, c, d)

    w ^= subkeys[124]
    x ^= subkeys[125]
    y ^= subkeys[126]
    z ^= subkeys[127]

    for k in range(30, -1, -1):
        j = 4 * k
        c = ROR(y, 22)
        a = ROR(w, 5)
        c = c ^ z ^ ((x<<7) & 0xFFFFFFFF)
        a = a ^ x ^ z
        d = ROR(z, 7)
        b = ROR(x, 1)
        d = d ^ c ^ ((a<<3) & 0xFFFFFFFF)
        b = b ^ a ^ c
        c = ROR(c, 3)
        a = ROR(a, 13)
        w, x, y, z = RNDS[k % 8](a, b, c, d)
        w ^= subkeys[j + 0]
        x ^= subkeys[j + 1]
        y ^= subkeys[j + 2]
        z ^= subkeys[j + 3]

    if swap:
        return pack('<4L', w, x, y, z)
    else:
        return pack('>4L', z, y, x, w)
