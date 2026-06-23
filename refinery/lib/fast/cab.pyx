# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
"""
Fast implementation of the CAB data block checksum. The pure Python fallback lives in
`refinery.lib.cab`.
"""
from libc.stdint cimport uint8_t, uint32_t


def cab_data_checksum(data, uint32_t checksum=0):
    cdef const uint8_t[::1] buf = data
    cdef Py_ssize_t n = buf.shape[0]
    cdef Py_ssize_t full = n - (n & 3)
    cdef Py_ssize_t i = 0
    cdef uint32_t acc = checksum
    cdef uint32_t tail = 0
    cdef int k = <int>(n & 3)
    cdef int s
    while i < full:
        acc ^= buf[i] | (<uint32_t>buf[i + 1] << 8) | (<uint32_t>buf[i + 2] << 16) | (<uint32_t>buf[i + 3] << 24)
        i += 4
    if k:
        s = (k - 1) * 8
        while i < n:
            tail |= <uint32_t>buf[i] << s
            s -= 8
            i += 1
        acc ^= tail
    return acc
