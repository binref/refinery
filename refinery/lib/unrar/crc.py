"""
CRC32, BLAKE2sp, and hash verification for RAR archives.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
import zlib

from refinery.lib.types import buf
from refinery.lib.unrar.headers import HashType


def crc32(data: bytes | memoryview, init: int = 0) -> int:
    """
    Compute CRC32 consistent with unrar conventions.
    """
    return zlib.crc32(data, init) & 0xFFFFFFFF


def checksum14(data: bytes | memoryview, init: int = 0) -> int:
    """
    RAR 1.4 16-bit checksum.
    """
    crc = init & 0xFFFF
    for b in data:
        crc = (crc + b) & 0xFFFF
        crc = ((crc << 1) | (crc >> 15)) & 0xFFFF
    return crc


_crc_table: list[int] | None = None


def _init_crc_table() -> list[int]:
    global _crc_table
    if _crc_table is not None:
        return _crc_table
    table = [0] * 256
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = (c >> 1) ^ 0xEDB88320
            else:
                c >>= 1
        table[i] = c & 0xFFFFFFFF
    _crc_table = table
    return table


def crc_table() -> list[int]:
    """
    Return the standard CRC32 lookup table used by legacy encryption.
    """
    return _init_crc_table()


BLAKE2S_BLOCKBYTES = 64
BLAKE2S_OUTBYTES = 32
PARALLELISM_DEGREE = 8

BLAKE2S_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

BLAKE2S_SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)

_M32 = 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _M32


class _Blake2sState:
    t: list[int]
    h: list[int]
    f: list[int]

    def __init__(self):
        self.h = list(BLAKE2S_IV)
        self.t = [0, 0]
        self.f = [0, 0]
        self.buf = bytearray(2 * BLAKE2S_BLOCKBYTES)
        self.buflen = 0
        self.last_node = 0

    def init_param(self, node_offset: int, node_depth: int):
        self.h = list(BLAKE2S_IV)
        self.t = [0, 0]
        self.f = [0, 0]
        self.buf = bytearray(2 * BLAKE2S_BLOCKBYTES)
        self.buflen = 0
        self.h[0] ^= 0x02080020
        self.h[2] ^= node_offset & _M32
        self.h[3] ^= ((node_depth << 16) | 0x20000000) & _M32

    def _compress(self, block: bytes | bytearray | memoryview):
        m = list(struct.unpack_from('<16I', block))
        v = list(self.h) + list(BLAKE2S_IV)
        v[12] ^= self.t[0]
        v[13] ^= self.t[1]
        v[14] ^= self.f[0]
        v[15] ^= self.f[1]

        for r in range(10):
            s = BLAKE2S_SIGMA[r]
            v[0] = (v[0] + v[4] + m[s[0]]) & _M32
            v[12] = _rotr32(v[12] ^ v[0], 16)
            v[8] = (v[8] + v[12]) & _M32
            v[4] = _rotr32(v[4] ^ v[8], 12)
            v[0] = (v[0] + v[4] + m[s[1]]) & _M32
            v[12] = _rotr32(v[12] ^ v[0], 8)
            v[8] = (v[8] + v[12]) & _M32
            v[4] = _rotr32(v[4] ^ v[8], 7)

            v[1] = (v[1] + v[5] + m[s[2]]) & _M32
            v[13] = _rotr32(v[13] ^ v[1], 16)
            v[9] = (v[9] + v[13]) & _M32
            v[5] = _rotr32(v[5] ^ v[9], 12)
            v[1] = (v[1] + v[5] + m[s[3]]) & _M32
            v[13] = _rotr32(v[13] ^ v[1], 8)
            v[9] = (v[9] + v[13]) & _M32
            v[5] = _rotr32(v[5] ^ v[9], 7)

            v[2] = (v[2] + v[6] + m[s[4]]) & _M32
            v[14] = _rotr32(v[14] ^ v[2], 16)
            v[10] = (v[10] + v[14]) & _M32
            v[6] = _rotr32(v[6] ^ v[10], 12)
            v[2] = (v[2] + v[6] + m[s[5]]) & _M32
            v[14] = _rotr32(v[14] ^ v[2], 8)
            v[10] = (v[10] + v[14]) & _M32
            v[6] = _rotr32(v[6] ^ v[10], 7)

            v[3] = (v[3] + v[7] + m[s[6]]) & _M32
            v[15] = _rotr32(v[15] ^ v[3], 16)
            v[11] = (v[11] + v[15]) & _M32
            v[7] = _rotr32(v[7] ^ v[11], 12)
            v[3] = (v[3] + v[7] + m[s[7]]) & _M32
            v[15] = _rotr32(v[15] ^ v[3], 8)
            v[11] = (v[11] + v[15]) & _M32
            v[7] = _rotr32(v[7] ^ v[11], 7)

            v[0] = (v[0] + v[5] + m[s[8]]) & _M32
            v[15] = _rotr32(v[15] ^ v[0], 16)
            v[10] = (v[10] + v[15]) & _M32
            v[5] = _rotr32(v[5] ^ v[10], 12)
            v[0] = (v[0] + v[5] + m[s[9]]) & _M32
            v[15] = _rotr32(v[15] ^ v[0], 8)
            v[10] = (v[10] + v[15]) & _M32
            v[5] = _rotr32(v[5] ^ v[10], 7)

            v[1] = (v[1] + v[6] + m[s[10]]) & _M32
            v[12] = _rotr32(v[12] ^ v[1], 16)
            v[11] = (v[11] + v[12]) & _M32
            v[6] = _rotr32(v[6] ^ v[11], 12)
            v[1] = (v[1] + v[6] + m[s[11]]) & _M32
            v[12] = _rotr32(v[12] ^ v[1], 8)
            v[11] = (v[11] + v[12]) & _M32
            v[6] = _rotr32(v[6] ^ v[11], 7)

            v[2] = (v[2] + v[7] + m[s[12]]) & _M32
            v[13] = _rotr32(v[13] ^ v[2], 16)
            v[8] = (v[8] + v[13]) & _M32
            v[7] = _rotr32(v[7] ^ v[8], 12)
            v[2] = (v[2] + v[7] + m[s[13]]) & _M32
            v[13] = _rotr32(v[13] ^ v[2], 8)
            v[8] = (v[8] + v[13]) & _M32
            v[7] = _rotr32(v[7] ^ v[8], 7)

            v[3] = (v[3] + v[4] + m[s[14]]) & _M32
            v[14] = _rotr32(v[14] ^ v[3], 16)
            v[9] = (v[9] + v[14]) & _M32
            v[4] = _rotr32(v[4] ^ v[9], 12)
            v[3] = (v[3] + v[4] + m[s[15]]) & _M32
            v[14] = _rotr32(v[14] ^ v[3], 8)
            v[9] = (v[9] + v[14]) & _M32
            v[4] = _rotr32(v[4] ^ v[9], 7)

        for i in range(8):
            self.h[i] = (self.h[i] ^ v[i] ^ v[i + 8]) & _M32

    def _increment_counter(self, inc: int):
        self.t[0] = (self.t[0] + inc) & _M32
        if self.t[0] < inc:
            self.t[1] = (self.t[1] + 1) & _M32

    def _set_lastblock(self):
        if self.last_node:
            self.f[1] = _M32
        self.f[0] = _M32

    def update(self, data: bytes | memoryview):
        offset = 0
        inlen = len(data)
        while inlen > 0:
            left = self.buflen
            fill = 2 * BLAKE2S_BLOCKBYTES - left
            if inlen > fill:
                self.buf[left:left + fill] = data[offset:offset + fill]
                self.buflen += fill
                self._increment_counter(BLAKE2S_BLOCKBYTES)
                self._compress(self.buf[:BLAKE2S_BLOCKBYTES])
                self.buf[:BLAKE2S_BLOCKBYTES] = self.buf[BLAKE2S_BLOCKBYTES:2 * BLAKE2S_BLOCKBYTES]
                self.buflen -= BLAKE2S_BLOCKBYTES
                offset += fill
                inlen -= fill
            else:
                self.buf[left:left + inlen] = data[offset:offset + inlen]
                self.buflen += inlen
                break

    def final(self) -> bytes:
        if self.buflen > BLAKE2S_BLOCKBYTES:
            self._increment_counter(BLAKE2S_BLOCKBYTES)
            self._compress(self.buf[:BLAKE2S_BLOCKBYTES])
            self.buflen -= BLAKE2S_BLOCKBYTES
            self.buf[:self.buflen] = self.buf[BLAKE2S_BLOCKBYTES:BLAKE2S_BLOCKBYTES + self.buflen]

        self._increment_counter(self.buflen)
        self._set_lastblock()
        pad_len = 2 * BLAKE2S_BLOCKBYTES - self.buflen
        self.buf[self.buflen:self.buflen + pad_len] = b'\x00' * pad_len
        self._compress(self.buf[:BLAKE2S_BLOCKBYTES])

        return struct.pack('<8I', *self.h)


class Blake2sp:
    """
    BLAKE2sp: 8-way parallel BLAKE2s tree hash.
    """
    def __init__(self):
        self._root = _Blake2sState()
        self._root.init_param(0, 1)  # root node
        self._leaves = []
        for i in range(PARALLELISM_DEGREE):
            s = _Blake2sState()
            s.init_param(i, 0)  # leaf node
            self._leaves.append(s)
        self._root.last_node = 1
        self._leaves[PARALLELISM_DEGREE - 1].last_node = 1
        self._buf = bytearray(PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES)
        self._buflen = 0

    def update(self, data: bytes | memoryview):
        offset = 0
        inlen = len(data)
        left = self._buflen
        fill = len(self._buf) - left

        if left and inlen >= fill:
            self._buf[left:left + fill] = data[offset:offset + fill]
            for i in range(PARALLELISM_DEGREE):
                start = i * BLAKE2S_BLOCKBYTES
                self._leaves[i].update(self._buf[start:start + BLAKE2S_BLOCKBYTES])
            offset += fill
            inlen -= fill
            left = 0

        block_set = PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES
        while inlen >= block_set:
            for i in range(PARALLELISM_DEGREE):
                start = offset + i * BLAKE2S_BLOCKBYTES
                self._leaves[i].update(data[start:start + BLAKE2S_BLOCKBYTES])
            offset += block_set
            inlen -= block_set

        if inlen > 0:
            self._buf[left:left + inlen] = data[offset:offset + inlen]
        self._buflen = left + inlen

    def digest(self) -> bytes:
        hashes = []
        for i in range(PARALLELISM_DEGREE):
            leaf = _Blake2sState()
            leaf.h = list(self._leaves[i].h)
            leaf.t = list(self._leaves[i].t)
            leaf.f = list(self._leaves[i].f)
            leaf.buf = bytearray(self._leaves[i].buf)
            leaf.buflen = self._leaves[i].buflen
            leaf.last_node = self._leaves[i].last_node

            if self._buflen > i * BLAKE2S_BLOCKBYTES:
                remaining = self._buflen - i * BLAKE2S_BLOCKBYTES
                if remaining > BLAKE2S_BLOCKBYTES:
                    remaining = BLAKE2S_BLOCKBYTES
                start = i * BLAKE2S_BLOCKBYTES
                leaf.update(self._buf[start:start + remaining])
            hashes.append(leaf.final())

        root = _Blake2sState()
        root.init_param(0, 1)
        root.last_node = 1
        for h in hashes:
            root.update(h)
        return root.final()


def blake2sp_hash(data: buf) -> bytes:
    """
    Compute BLAKE2sp hash of data (32 bytes output).
    """
    h = Blake2sp()
    h.update(data)
    return h.digest()


def convert_hash_to_mac(
    hash_type: int,
    hash_key: bytes,
    crc_value: int = 0,
    digest: bytes = b''
) -> tuple[int, bytes]:
    """
    Convert a hash result to HMAC-based MAC for encrypted RAR5 file verification.
    """
    if hash_type == HashType.HASH_CRC32:
        data = struct.pack('<I', crc_value)
        mac = hmac.new(hash_key, data, hashlib.sha256).digest()
        result = 0
        for i in range(32):
            result ^= mac[i] << ((i & 3) * 8)
        return result & 0xFFFFFFFF, b''

    if hash_type == HashType.HASH_BLAKE2:
        mac = hmac.new(hash_key, digest, hashlib.sha256).digest()
        return 0, mac

    return 0, b''
