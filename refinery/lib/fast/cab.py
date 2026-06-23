"""
Pure-Python implementation of the CAB data block checksum. The Cython version in `cab.pyx` is used
instead when it has been compiled.
"""
from __future__ import annotations


def cab_data_checksum(data: memoryview, checksum: int = 0) -> int:
    """
    Computes the CAB data block checksum: the XOR of all little-endian 32-bit words in `data`,
    combined with the big-endian value of the trailing one to three bytes. The words are XOR-folded
    in halves so the reduction is a handful of big-integer operations rather than one Python-level
    iteration per word.
    """
    k = len(data) % 4
    if body := len(data) - k:
        words = body >> 2
        padded = 1
        while padded < words:
            padded <<= 1
        value = int.from_bytes(data[:body], 'little')
        half = padded << 5
        while half > 32:
            half >>= 1
            value = (value >> half) ^ (value & ((1 << half) - 1))
        checksum ^= value & 0xFFFFFFFF
    if k:
        checksum ^= int.from_bytes(data[-k:], 'big')
    return checksum
