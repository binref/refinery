# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
cimport cython

from libc.stdint cimport uint8_t, uint32_t, uint64_t

cdef uint32_t CRC32_TABLE[256]

cdef void _init_crc32_table():
    cdef uint32_t c
    cdef int i, j
    for i in range(256):
        c = i
        for j in range(8):
            if c & 1:
                c = (c >> 1) ^ 0xEDB88320
            else:
                c = c >> 1
        CRC32_TABLE[i] = c

_init_crc32_table()


def decrypt(
    password,
    data,
    uint32_t state_X,
    uint32_t state_Y,
    uint32_t state_Z
):
    cdef:
        uint32_t X = state_X
        uint32_t Y = state_Y
        uint32_t Z = state_Z
        uint32_t t
        uint8_t c
        int k = len(password)
        int n = len(data)
        const uint8_t[::1] pv = memoryview(password)
        const uint8_t[::1] dv = memoryview(data)
        int i
        bytearray output = bytearray(n)
        uint8_t[::1] ov = output
    with nogil:
        for i in range(k):
            c = pv[i]
            X = (X >> 8) ^ CRC32_TABLE[(X ^ c) & 0xFF]
            Y += X & 0xFF
            Y *= 134775813UL
            Y += 1UL
            Z = (Z >> 8) ^ CRC32_TABLE[(Z ^ (Y >> 24)) & 0xFF]
        for i in range(n):
            t = Z | 2
            c = dv[i] ^ (((t * (t ^ 1)) >> 8) & 0xFF)
            ov[i] = c
            X = (X >> 8) ^ CRC32_TABLE[(X ^ c) & 0xFF]
            Y += X & 0xFF
            Y *= 134775813UL
            Y += 1UL
            Z = (Z >> 8) ^ CRC32_TABLE[(Z ^ (Y >> 24)) & 0xFF]
    return output, X, Y, Z
