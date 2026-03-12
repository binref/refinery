"""
Pure-Python implementation of the Twofish block cipher, based on the specification by Bruce
Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson.
"""
from __future__ import annotations

import struct

from refinery.lib.crypto import BlockCipher, BufferType, CipherMode, rotl32, rotr32

_MASK32 = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# q-permutation tables (q0 and q1) from the Twofish specification.
# Each q-permutation is a fixed 8-bit permutation built from four 4-bit
# permutations (t0..t3) via a specific Feistel-like structure.
# We compute them once at module load time.
# ---------------------------------------------------------------------------

# The four 4-bit permutations for q0
_Q0_T0 = (0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4)
_Q0_T1 = (0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD)
_Q0_T2 = (0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1)
_Q0_T3 = (0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA)

# The four 4-bit permutations for q1
_Q1_T0 = (0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5)
_Q1_T1 = (0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8)
_Q1_T2 = (0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF)
_Q1_T3 = (0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA)


def _build_q_perm(t0, t1, t2, t3):
    """
    Build one of the q permutation tables (q0 or q1) from its four 4-bit sub-permutations,
    following Twofish specification Section 4.3.2.
    """
    q = [0] * 256
    for x in range(256):
        a0, b0 = x >> 4, x & 0xF
        a1 = a0 ^ b0
        b1 = a0 ^ ((b0 >> 1) | ((b0 & 1) << 3)) ^ ((8 * a0) & 0xF)
        a2, b2 = t0[a1], t1[b1]
        a3 = a2 ^ b2
        b3 = a2 ^ ((b2 >> 1) | ((b2 & 1) << 3)) ^ ((8 * a2) & 0xF)
        a4, b4 = t2[a3], t3[b3]
        q[x] = (b4 << 4) | a4
    return q


_Q0 = _build_q_perm(_Q0_T0, _Q0_T1, _Q0_T2, _Q0_T3)
_Q1 = _build_q_perm(_Q1_T0, _Q1_T1, _Q1_T2, _Q1_T3)
_QQ = [_Q0, _Q1]

# ---------------------------------------------------------------------------
# MDS matrix multiplication in GF(2^8) mod x^8+x^6+x^5+x^3+1 (0x169)
# ---------------------------------------------------------------------------

_MDS_POLY = 0x169


def _mds_column_mult(x: int, col: int) -> int:
    """
    Multiply a single byte x by column `col` of the MDS matrix, returning a 32-bit result.
    Uses GF(2^8) multiplication with polynomial 0x169.

    The MDS column definitions from the Twofish reference code:

        col 0: [x01, x5B, xEF, xEF]
        col 1: [xEF, xEF, x5B, x01]
        col 2: [x5B, xEF, x01, xEF]
        col 3: [x5B, x01, xEF, x5B]

    where xAB = gf_mult(x, 0xAB, 0x169)
    """
    x01 = x
    x5B = _gf_mult(x, 0x5B, _MDS_POLY)
    xEF = _gf_mult(x, 0xEF, _MDS_POLY)

    if col == 0:
        return x01 | (x5B << 8) | (xEF << 16) | (xEF << 24)
    elif col == 1:
        return xEF | (xEF << 8) | (x5B << 16) | (x01 << 24)
    elif col == 2:
        return x5B | (xEF << 8) | (x01 << 16) | (xEF << 24)
    else:
        return x5B | (x01 << 8) | (xEF << 16) | (x5B << 24)


def _gf_mult(a: int, b: int, p: int) -> int:
    """
    Multiply two elements in GF(2^8) with the given modular polynomial.
    """
    result = 0
    a &= 0xFF
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= p & 0xFF
    return result


# Precompute MDS lookup tables: _MDS[col][byte] -> 32-bit word
_MDS = [[0] * 256 for _ in range(4)]
for _col in range(4):
    for _i in range(256):
        _MDS[_col][_i] = _mds_column_mult(_i, _col)

# ---------------------------------------------------------------------------
# Reed-Solomon code: GF(2^8) mod x^8+x^6+x^3+x^2+1 (0x14D)
# Used to derive the S-box key words from the original key material.
# ---------------------------------------------------------------------------

_RS_POLY = 0x14D

# RS matrix from the Twofish specification (4x8):
_RS_MATRIX = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
]


def _rs_mds_encode(k0: int, k1: int) -> int:
    """
    Use the Reed-Solomon [8,4] code over GF(2^8) / 0x14D to compute one 32-bit S-box key word from
    two 32-bit key halves (8 key bytes total). Here, `k0` and `k1` are little-endian 32-bit words.
    """
    # Extract 8 input bytes in little-endian order
    inp = []
    for v in (k0, k1):
        for shift in range(0, 32, 8):
            inp.append((v >> shift) & 0xFF)

    result = 0
    for row in range(4):
        val = 0
        for col in range(8):
            val ^= _gf_mult(_RS_MATRIX[row][col], inp[col], _RS_POLY)
        result |= val << (row * 8)
    return result


# ---------------------------------------------------------------------------
# q-box usage orderings for the h function.
# qord[byte_position][layer] gives the q-permutation index (0 or 1) to use.
# The layers are indexed 0..4 from outermost to innermost.
# For k key groups, we use the last k+1 entries: indices (5-k-1) to 4.
# ---------------------------------------------------------------------------

_QORD = [
    [1, 1, 0, 0, 1],  # byte 0
    [0, 1, 1, 0, 0],  # byte 1
    [0, 0, 0, 1, 1],  # byte 2
    [1, 0, 1, 1, 0],  # byte 3
]

# ---------------------------------------------------------------------------
# The h function from the Twofish specification (Section 4.3.5)
# ---------------------------------------------------------------------------


def _h_func(x: int, key_list: list[int], k: int) -> int:
    """
    The h function: maps a 32-bit input X through k+1 layers of q-permutations with k layers of key
    XOR between them, then through the MDS matrix. `k` is the number of 64-bit key groups:
    - 2 for 128-bit
    - 3 for 192-bit
    - 4 for 256-bit

    The function processes each of the 4 input bytes independently through a chain of q-permutation
    lookups interleaved with key byte XORs:

           q-box -> XOR key[k-1]
        -> q-box -> XOR key[k-2] -> ... -> XOR key[0]
        -> q-box -> MDS

    That is k+1 q-box lookups and k key XOR operations. The final q-box lookup feeds directly into
    the MDS matrix multiply with no trailing XOR. The q-box permutation used at each layer and byte
    position is defined by the qord table from the Twofish specification.

    key_list: list of k 32-bit words. For the key schedule, these are Me or Mo words. For the g
    function, these are S-box key bytes stored as [S0, S1, ...] (NOT reversed).
    """
    b = [
        x & 0xFF,
        (x >> 8) & 0xFF,
        (x >> 16) & 0xFF,
        (x >> 24) & 0xFF,
    ]

    # The starting index in qord for k key groups
    start = 5 - k - 1

    # First q-box layer (no preceding key XOR)
    for i in range(4):
        b[i] = _QQ[_QORD[i][start]][b[i]]

    # k layers of: key XOR, then q-box
    for j in range(k):
        key_word = key_list[k - 1 - j]
        for i in range(4):
            b[i] ^= (key_word >> (i * 8)) & 0xFF
            b[i] = _QQ[_QORD[i][start + 1 + j]][b[i]]

    # MDS matrix multiply
    return _MDS[0][b[0]] ^ _MDS[1][b[1]] ^ _MDS[2][b[2]] ^ _MDS[3][b[3]]


# ---------------------------------------------------------------------------
# Twofish block cipher
# ---------------------------------------------------------------------------

_SK_STEP = 0x02020202
_SK_BUMP = 0x01010101
_SK_ROTL = 9


class Twofish(BlockCipher):
    """
    Pure-Python Twofish block cipher implementation. Supports 128, 192, and 256 bit keys.
    """
    block_size = 16
    key_size = frozenset({16, 24, 32})

    _subkeys: list[int]
    _sbox_keys: list[int]
    _k: int

    @property
    def key(self):
        return self._key_bytes

    @key.setter
    def key(self, key: bytes):
        self._key_bytes = key
        key_len = len(key)
        self._k = k = key_len // 8  # number of 64-bit key words

        # Split key into 32-bit words, little-endian
        num_words = key_len // 4
        key_words = list(struct.unpack(f'<{num_words}I', key))

        # Even-indexed words form Me, odd-indexed words form Mo
        me_words = [key_words[2 * i] for i in range(k)]
        mo_words = [key_words[2 * i + 1] for i in range(k)]

        # Compute S-box keys using RS matrix
        s_keys = []
        for i in range(k):
            s_keys.append(_rs_mds_encode(key_words[2 * i], key_words[2 * i + 1]))
        self._sbox_keys = list(reversed(s_keys))  # Reversed so h_func accesses in correct order

        # Compute the 40 round subkeys
        subkeys = []
        for i in range(20):
            # A = h(2i * rho, Me)  where rho = 0x01010101
            a = _h_func(i * _SK_STEP, me_words, k)
            # B = ROL(h((2i+1) * rho, Mo), 8)
            b = _h_func(i * _SK_STEP + _SK_BUMP, mo_words, k)
            b = rotl32(b, 8)
            # PHT: K[2i] = A + B, K[2i+1] = ROL(A + 2B, 9)
            a_plus_b = (a + b) & _MASK32
            subkeys.append(a_plus_b)
            subkeys.append(rotl32((a_plus_b + b) & _MASK32, _SK_ROTL))
        self._subkeys = subkeys

    def _g_func(self, x: int) -> int:
        """
        Compute g(x) = h(x, S) through the key-dependent S-boxes and MDS.
        """
        return _h_func(x, self._sbox_keys, self._k)

    def block_encrypt(self, data: BufferType) -> BufferType:
        K = self._subkeys

        # Input whitening
        a, b, c, d = struct.unpack('<4I', bytes(data))
        a ^= K[0]
        b ^= K[1]
        c ^= K[2]
        d ^= K[3]

        # 16 Feistel rounds
        for r in range(16):
            t0 = self._g_func(a)
            t1 = self._g_func(rotl32(b, 8))
            # PHT + subkey addition
            f0 = (t0 + t1 + K[8 + 2 * r]) & _MASK32
            f1 = (t0 + 2 * t1 + K[9 + 2 * r]) & _MASK32
            c = rotr32(c ^ f0, 1)
            d = rotl32(d, 1) ^ f1
            # Swap halves
            a, b, c, d = c, d, a, b

        # Output whitening (no undo of last swap; c,d hold the last-modified
        # pair and correspond to ciphertext words 0,1)
        c ^= K[4]
        d ^= K[5]
        a ^= K[6]
        b ^= K[7]
        return struct.pack('<4I', c, d, a, b)

    def block_decrypt(self, data: BufferType) -> BufferType:
        K = self._subkeys

        # Undo output whitening
        c, d, a, b = struct.unpack('<4I', bytes(data))
        c ^= K[4]
        d ^= K[5]
        a ^= K[6]
        b ^= K[7]

        # 16 Feistel rounds in reverse
        for r in range(15, -1, -1):
            # Swap halves
            a, b, c, d = c, d, a, b

            t0 = self._g_func(a)
            t1 = self._g_func(rotl32(b, 8))
            f0 = (t0 + t1 + K[8 + 2 * r]) & _MASK32
            f1 = (t0 + 2 * t1 + K[9 + 2 * r]) & _MASK32
            c = rotl32(c, 1) ^ f0
            d = rotr32(d ^ f1, 1)

        # Undo input whitening
        a ^= K[0]
        b ^= K[1]
        c ^= K[2]
        d ^= K[3]
        return struct.pack('<4I', a, b, c, d)

    def __init__(self, key: BufferType, mode: CipherMode | None):
        super().__init__(key, mode)
