#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from operator import __lshift__, __rshift__
from typing import Iterable, List

from refinery.lib import chunks
from refinery.units.crypto.cipher import StreamCipherUnit


class isaac(StreamCipherUnit):
    """
    The ISAAC (Indirection, Shift, Accumulate, Add, Count) cipher.
    """

    def keystream(self) -> Iterable[int]:
        key = self.args.key

        A: int = 0
        B: int = 0
        C: int = 0
        S: List[int] = [0x9E3779B9] * 8
        T: List[int] = []
        K = list(chunks.unpack(key + bytearray(0x400 - len(key)), 4, bigendian=False))
        U = 0xFFFFFFFF

        def _mix_state():
            a, b, c, d, e, f, g, h = S
            a ^= (b << 0x0B) & U; d = d + a & U; b = b + c & U # noqa
            b ^= (c >> 0x02) & U; e = e + b & U; c = c + d & U # noqa
            c ^= (d << 0x08) & U; f = f + c & U; d = d + e & U # noqa
            d ^= (e >> 0x10) & U; g = g + d & U; e = e + f & U # noqa
            e ^= (f << 0x0A) & U; h = h + e & U; f = f + g & U # noqa
            f ^= (g >> 0x04) & U; a = a + f & U; g = g + h & U # noqa
            g ^= (h << 0x08) & U; b = b + g & U; h = h + a & U # noqa
            h ^= (a >> 0x09) & U; c = c + h & U; a = a + b & U # noqa
            S[:] = a, b, c, d, e, f, g, h
            return S

        def _initialize_with(R: List[int]):
            for i in range(0, 0x100, 8):
                S[:] = (x + R[j] & U for j, x in enumerate(S, i))
                T[i:i + 8] = _mix_state()

        for _ in range(4):
            _mix_state()

        _initialize_with(K)
        _initialize_with(T)

        operations = [
            (__lshift__, 0x0D),
            (__rshift__, 0x06),
            (__lshift__, 0x02),
            (__rshift__, 0x10),
        ]

        while True:
            C = (C + 1) & U
            B = (B + C) & U
            for i in range(0x100):
                X = T[i]
                shift, k = operations[i % 4]
                A = (A ^ shift(A, k)) & U
                A = (A + T[i ^ 0x80]) & U
                Y = T[+i] = T[X // 4 & 0xFF] + A + B & U
                B = K[~i] = X + T[Y // 1024 & 0xFF] & U
            yield from chunks.pack(K, 4, True)
