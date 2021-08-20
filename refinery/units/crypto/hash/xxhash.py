#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This code is based on a pure Python implementation of xxHash, sourced from the
following GitHub repository:

https://github.com/ifduyue/python-xxhash-pure

The original work is copyright (c) 2018-2019 Yue Du.

The source code has been modified to fit the code requirements of this project.

The original implementation is covered by a BSD-2-Clause license. Regardless of
the license used for the binary refinery, this code file is also subject to the
terms and conditions of a BSD-2-Clause license, which is included here:

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import struct

from . import HashUnit
from ....lib.crypto import rotl32


class xxhash:
    PRIME1 = 0x9E3779B1
    PRIME2 = 0x85EBCA77
    PRIME3 = 0xC2B2AE3D
    PRIME4 = 0x27D4EB2F
    PRIME5 = 0x165667B1

    @classmethod
    def xxhround(cls, a, b):
        return (rotl32(a + b * cls.PRIME2 & 0xFFFFFFFF, 13) * cls.PRIME1) & 0xFFFFFFFF

    @classmethod
    def xxhavalance(cls, h32):
        h32 &= 0xFFFFFFFF
        h32 ^= (h32 >> 15)
        h32 *= cls.PRIME2
        h32 &= 0xFFFFFFFF
        h32 ^= (h32 >> 13)
        h32 *= cls.PRIME3
        h32 &= 0xFFFFFFFF
        h32 ^= (h32 >> 16)
        return h32

    def __init__(self, data=B'', seed=0):
        self.seed = seed
        self.reset()
        self.update(data)

    def reset(self):
        seed = self.seed
        self.v1 = seed + self.PRIME1 + self.PRIME2
        self.v2 = seed + self.PRIME2
        self.v3 = seed + 0
        self.v4 = seed - self.PRIME1
        self.total_len = 0
        self.mem = bytearray(16)
        self.memsize = 0

    def update(self, data):
        if not data:
            return
        self.total_len += len(data)
        mv = memoryview(data)
        if self.memsize + len(mv) < 16:
            self.mem[self.memsize:self.memsize + len(mv)] = mv
            self.memsize += len(mv)
            return
        v1, v2, v3, v4 = self.v1, self.v2, self.v3, self.v4
        if self.memsize:
            self.mem[self.memsize:16] = mv[:16 - self.memsize]
            s1, s2, s3, s4 = struct.unpack('<IIII', self.mem)
            v1 = self.xxhround(v1, s1)
            v2 = self.xxhround(v2, s2)
            v3 = self.xxhround(v3, s3)
            v4 = self.xxhround(v4, s4)
            mv = mv[16 - self.memsize:]
            self.memsize = 0
        for i in range(0, len(mv), 16):
            bfr = mv[i:i + 16]
            if len(bfr) < 16: break
            s1, s2, s3, s4 = struct.unpack('<IIII', bfr)
            v1 = self.xxhround(v1, s1)
            v2 = self.xxhround(v2, s2)
            v3 = self.xxhround(v3, s3)
            v4 = self.xxhround(v4, s4)
        self.memsize = memsize = len(mv) - i
        assert memsize <= 16
        self.mem[:memsize] = mv[i:]
        self.v1, self.v2, self.v3, self.v4 = v1, v2, v3, v4

    def intdigest(self):
        v1, v2, v3, v4 = self.v1, self.v2, self.v3, self.v4
        if self.total_len >= 16:
            h32 = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)
        else:
            h32 = v3 + self.PRIME5
        h32 += self.total_len
        i = 0
        while i <= self.memsize - 4:
            val, = struct.unpack('<I', self.mem[i:i + 4])
            h32 += val * self.PRIME3
            h32 &= 0xFFFFFFFF
            h32 = rotl32(h32, 17) * self.PRIME4
            i += 4
        for c in self.mem[i:self.memsize]:
            h32 += c * self.PRIME5
            h32 &= 0xFFFFFFFF
            h32 = rotl32(h32, 11) * self.PRIME1
        return self.xxhavalance(h32)

    def digest(self):
        return struct.pack('>I', self.intdigest())

    def hexdigest(self):
        return '{:08x}'.format(self.intdigest())


class xxh(HashUnit):
    """
    Implements the xxHash hashing algorithm.
    """
    def _algorithm(self, data):
        return xxhash(data)
