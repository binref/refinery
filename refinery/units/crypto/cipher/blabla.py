#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
from refinery.units import Arg

from refinery.units.crypto.cipher import StreamCipherUnit
from refinery.lib.crypto import rotr64

_M64 = 0xFFFFFFFFFFFFFFFF


class blabla(StreamCipherUnit):
    """
    Implements the BlaBla cipher, a 256-bit stream cipher designed by Jean-Philippe Aumasson. It
    is similar to ChaCha in design but operates on 64-bit blocks.
    """
    key_size = {32}

    def __init__(
        self, key,
        nonce: Arg(help='The 16-byte nonce. The default are 16 null bytes.') = bytes(16),
        rounds: Arg.Number('-r', help='The number of rounds, default is {default}.') = 10,
        discard=0, stateful=False
    ):
        super().__init__(key=key, nonce=nonce, rounds=rounds, discard=discard, stateful=stateful)

    def keystream(self):
        r = self.args.rounds
        n = self.args.nonce
        k = struct.unpack('<4Q', self.args.key)

        try:
            n = struct.unpack('<2Q', n)
        except Exception:
            raise ValueError(F'The given nonce has invalid length of {len(n)}, it must be 16 bytes in size.')

        q = [
            0x6170786593810fab,  # 0x0
            0x3320646ec7398aee,  # 0x1
            0x79622d3217318274,  # 0x2
            0x6b206574babadada,  # 0x3
            *k,                  # 0x4 .. 0x7
            0x2ae36e593e46ad5f,  # 0x8
            0xb68f143029225fc9,  # 0x9
            0x8da1e08468303aa6,  # 0xA
            0xa48a209acd50a4a7,  # 0xB
            0x7fdc12f23f90778c,  # 0xC
            1,                   # 0xD
            *n                   # 0xE .. 0xF
        ]
        while True:
            v = [*q]
            for _ in range(r):
                for a, b, c, d in [
                    (0x0, 0x4, 0x8, 0xC),
                    (0x1, 0x5, 0x9, 0xD),
                    (0x2, 0x6, 0xA, 0xE),
                    (0x3, 0x7, 0xB, 0xF),
                    (0x0, 0x5, 0xA, 0xF),
                    (0x1, 0x6, 0xB, 0xC),
                    (0x2, 0x7, 0x8, 0xD),
                    (0x3, 0x4, 0x9, 0xE),
                ]:
                    v[a] = v[a] + v[b] & _M64
                    v[d] = rotr64(v[d] ^ v[a], 32)
                    v[c] = v[c] + v[d] & _M64
                    v[b] = rotr64(v[b] ^ v[c], 24)
                    v[a] = v[a] + v[b] & _M64
                    v[d] = rotr64(v[d] ^ v[a], 16)
                    v[c] = v[c] + v[d] & _M64
                    v[b] = rotr64(v[b] ^ v[c], 63)
            v = [x + y & _M64 for x, y in zip(q, v)]
            q[0xD] += 1
            yield from struct.pack('<16Q', *v)
