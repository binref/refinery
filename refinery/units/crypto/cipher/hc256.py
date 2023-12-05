#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure Python implementation of HC-128
"""
from typing import Iterable, Sequence, Iterator

import array
import itertools

from refinery.lib.crypto import rotr32
from refinery.units.crypto.cipher import StreamCipherUnit, Arg


def _H(q: Sequence[int], u: int) -> int:
    return (
        + q[         u         & 0xFF ] # noqa
        + q[0x100 + (u >> 0x08 & 0xFF)] # noqa
        + q[0x200 + (u >> 0x10 & 0xFF)] # noqa
        + q[0x300 + (u >> 0x18 & 0xFF)] # noqa
    ) & 0xFFFFFFFF


def _F1(x: int) -> int:
    return rotr32(x, 0x07) ^ rotr32(x, 0x12) ^ (x >> 0x3)


def _F2(x: int) -> int:
    return rotr32(x, 0x11) ^ rotr32(x, 0x13) ^ (x >> 0xA)


class HC256(Iterator[int]):
    _p: array.ArrayType
    _q: array.ArrayType
    _c: int

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 0x20:
            raise ValueError('invalid key length')
        if len(iv) != 0x20:
            raise ValueError('invalid iv length')
        for t in array.typecodes:
            if not t.isupper():
                continue
            w = array.array(t)
            if w.itemsize == 4:
                break
        else:
            raise ValueError('no matching array type found')
        w.frombytes(key)
        w.frombytes(iv)
        w.extend(itertools.repeat(0, 0xA00 - len(w)))
        for k in range(0x10, 0xA00):
            a = _F2(w[k - 0x2])
            b = _F1(w[k - 0xF])
            w[k] = a + w[k - 7] + b + w[k - 16] + k & 0xFFFFFFFF
        self._p = w[0x200:0x600]
        self._q = w[0x600:0xA00]
        self._c = 0
        for _ in range(0x1000):
            next(self)

    def __next__(self) -> int:
        k = self._c & 0x3FF
        a = k - 0x3 & 0x3FF
        b = k - 0xA & 0x3FF
        c = k - 0xC & 0x3FF
        d = k + 0x1 & 0x3FF
        p = self._p
        q = self._q
        if self._c >= 0x400:
            p, q = q, p
        prot = rotr32(p[a], 10) ^ rotr32(p[d], 23)
        qpos = (p[a] ^ p[d]) & 0x3FF
        p[k] = p[k] + p[b] + prot + q[qpos] & 0xFFFFFFFF
        self._c = (self._c + 1) & 0x7FF
        return _H(q, p[c]) ^ p[k]


class hc256(StreamCipherUnit):
    """
    HC-256 encryption and decryption.
    """
    key_size = {32}

    def __init__(
        self, key,
        iv: Arg(help='An initialization vector; the default is a sequence of 32 zero bytes.') = bytes(32),
        discard=0, stateful=False,
    ):
        super().__init__(key=key, iv=iv, stateful=stateful, discard=discard)
        self._keystream = None

    def keystream(self) -> Iterable[int]:
        for num in HC256(self.args.key, self.args.iv):
            yield from num.to_bytes(4, 'little')
